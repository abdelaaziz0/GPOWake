from __future__ import annotations

import json
import os
import stat
import struct
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from gpowake.cli import _parser
from gpowake.catalog import (
    REGISTRY_CSE_GUID,
    SECURITY_CSE_GUID,
    setting_from_dict,
)
from gpowake.acl import GPLINK_GUID
from gpowake.models import (
    AccessDecision,
    GptAccessObservation,
    GptAccessProbe,
    GptAccessSource,
    Link,
    Setting,
    SettingKind,
    Severity,
    ValueSensitivity,
)
from gpowake.observations import (
    GPT_FILE_GENERIC_READ,
    machine_credential_matches,
    token_sids_sha256,
)
from gpowake.parsers.registry_pol import REG_SZ, parse_registry_pol
from gpowake.precedence import PolicyEngine
from gpowake.redaction import SECRET_MARKER
from gpowake.report import (
    finding_to_dict,
    iter_jsonl,
    render_explanation,
    render_netexec,
    render_text,
    report_document,
    write_json_report,
)
from gpowake.snapshot import save_snapshot
from gpowake.solver import CounterfactualSolver
from scripts.generate_release_metadata import generate

from conftest import DANGEROUS_DN, SAFE_DN, environment, som_sd


SENTINEL = "GPOWAKE-SENTINEL-" + "PASSWORD-DO-NOT-LEAK"
GPT_TMPL = "Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf"
REGISTRY_POL = "Machine\\Registry.pol"


def _wide(value: str) -> bytes:
    return value.encode("utf-16-le")


def _registry_pol_with_password(secret: str) -> bytes:
    raw = _wide(secret + "\x00")
    return (
        b"PReg"
        + struct.pack("<I", 1)
        + b"[\x00"
        + _wide("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon;")
        + _wide("DefaultPassword;")
        + struct.pack("<I", REG_SZ)
        + b";\x00"
        + struct.pack("<I", len(raw))
        + b";\x00"
        + raw
        + b"]\x00"
    )


def test_secret_is_destroyed_and_redacted_from_every_artifact(
    tmp_path, base_environment
) -> None:
    setting = parse_registry_pol(_registry_pol_with_password(SENTINEL))[0]
    assert setting.value_sensitivity is ValueSensitivity.SECRET
    assert setting.value == {"type": REG_SZ, "secret_present": True}
    assert SENTINEL not in repr(setting)
    imported = setting_from_dict(
        {
            "kind": "REGISTRY",
            "name": (
                "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\"
                "DefaultPassword"
            ),
            "value": {"type": REG_SZ, "data": SENTINEL},
        }
    )
    assert imported.value_sensitivity is ValueSensitivity.SECRET
    assert SENTINEL not in repr(imported)
    findings = CounterfactualSolver(base_environment).solve()
    assert findings

    # Snapshot serialization must fail closed even if an in-process caller
    # constructs a malformed SECRET-labelled object containing the literal.
    tainted_setting = replace(
        setting,
        value={"type": REG_SZ, "data": SENTINEL},
    )
    gpo = base_environment.gpo(DANGEROUS_DN)
    assert gpo is not None
    base_environment.gpos[gpo.dn.casefold()] = replace(
        gpo, settings=(tainted_setting,)
    )
    snapshot = tmp_path / "secret-snapshot.json"
    save_snapshot(base_environment, snapshot)
    assert SENTINEL not in snapshot.read_text(encoding="utf-8")
    if os.name == "posix":
        assert stat.S_IMODE(snapshot.stat().st_mode) == 0o600

    tainted = replace(
        findings[0],
        dormant_value=SENTINEL,
        result_value=SENTINEL,
        current_value=SENTINEL,
        value_sensitivity=ValueSensitivity.SECRET,
        current_value_sensitivity=ValueSensitivity.SECRET,
    )
    rendered = {
        "text": render_text([tainted]),
        "netexec": render_netexec([tainted]),
        "jsonl": "".join(iter_jsonl([tainted])),
        "explain": render_explanation(
            {
                **finding_to_dict(tainted),
                "result_value": SENTINEL,
                "current_value": SENTINEL,
                "value_sensitivity": "SECRET",
            }
        ),
    }
    report = tmp_path / "secret-report.json"
    rendered["json"] = write_json_report(report_document([tainted]), report)
    if os.name == "posix":
        assert stat.S_IMODE(report.stat().st_mode) == 0o600
    assert all(SENTINEL not in output for output in rendered.values())
    assert SECRET_MARKER["secret_present"] is True


def test_machine_credential_match_requires_exact_domain_and_account() -> None:
    target = environment(include_safe=False).targets[0]
    assert machine_credential_matches(target, "CORP\\SRV1$")
    assert machine_credential_matches(target, "SRV1$@corp.local")
    assert not machine_credential_matches(target, "EVILTRUST\\SRV1$")
    assert not machine_credential_matches(target, "SRV1$@evil.example")
    assert not machine_credential_matches(target, "SRV1$")
    assert not machine_credential_matches(target, "CORP\\SRV2$")


def test_partial_gpt_denial_is_scoped_to_the_registry_family() -> None:
    env = environment(
        ou_links=(Link(DANGEROUS_DN, 0, 2), Link(SAFE_DN, 0, 1)),
        ou_sd=som_sd(GPLINK_GUID),
    )
    now = datetime.now(timezone.utc).isoformat()
    env.collected_at = now
    env.source_dc = "dc01.corp.local"
    registry = Setting(
        SettingKind.REGISTRY,
        "Software\\Example\\Danger",
        {"type": 4, "data": 1},
        dangerous=True,
        severity=Severity.HIGH,
        required_extension=REGISTRY_CSE_GUID,
    )
    gpo = env.gpo(DANGEROUS_DN)
    assert gpo is not None
    gpo = replace(
        gpo,
        functionality_version=2,
        machine_extensions=(SECURITY_CSE_GUID, REGISTRY_CSE_GUID),
        settings=(*gpo.settings, registry),
        file_sys_path=(
            f"\\\\dc01.corp.local\\SYSVOL\\corp.local\\Policies\\{gpo.guid}"
        ),
        version_number=7,
        gpt_version=7,
        gpt_hashes=(
            ("gpt.ini", "a" * 64),
            (GPT_TMPL, "b" * 64),
            (REGISTRY_POL, "c" * 64),
        ),
        gpt_file_sizes=(("gpt.ini", 1), (GPT_TMPL, 2), (REGISTRY_POL, 3)),
    )
    env.gpos[gpo.dn.casefold()] = gpo
    safe = env.gpo(SAFE_DN)
    assert safe is not None
    env.gpos[safe.dn.casefold()] = replace(safe, functionality_version=2)
    target = env.targets[0]
    observation = GptAccessObservation(
        gpo.dn,
        AccessDecision.UNKNOWN,
        GptAccessSource.WINDOWS_AUTHZ_ACCESSCHECK,
        "lab-windows-token-oracle",
        "1.0",
        "d" * 64,
        now,
        GPT_FILE_GENERIC_READ,
        f"\\\\dc01.corp.local\\SYSVOL\\corp.local\\Policies\\{gpo.guid}",
        "dc01.corp.local",
        target.sid,
        token_sids_sha256(target),
        "CORP\\SRV1$",
        target.sid,
        "WINDOWS_TOKEN_USER",
        7,
        7,
        "e" * 64,
        "f" * 64,
        (
            GptAccessProbe("gpt.ini", "READ_OK", "a" * 64, 1),
            GptAccessProbe(GPT_TMPL, "READ_OK", "b" * 64, 2),
            GptAccessProbe(REGISTRY_POL, "ACCESS_DENIED"),
        ),
    )
    env.targets[0] = replace(
        target,
        gpt_read_observations=(observation,),
        gpt_read_decisions=((SAFE_DN, AccessDecision.ALLOW),),
    )

    assert env.targets[0].gpt_read_decision_for(
        gpo, SettingKind.PRIVILEGE_RIGHT
    ) is AccessDecision.ALLOW
    assert env.targets[0].gpt_read_decision_for(
        gpo, SettingKind.REGISTRY
    ) is AccessDecision.DENY
    evaluation = PolicyEngine(env).evaluate(env.targets[0])
    assert gpo.settings[0].key in evaluation.winners
    assert evaluation.winners[gpo.settings[0].key].gpo.dn == SAFE_DN
    assert registry.key not in evaluation.winners
    reason, _winner = PolicyEngine(env).dormancy_reason(evaluation, gpo, registry)
    assert reason.value == "GPT_UNREADABLE"
    findings = CounterfactualSolver(env).solve()
    assert [item.setting_kind for item in findings] == [SettingKind.PRIVILEGE_RIGHT]


def test_secure_credential_file_rejects_group_or_world_access(tmp_path) -> None:
    from gpowake.secure_io import read_secure_file

    if os.name == "nt":
        pytest.skip("native Windows requires descriptor/prompt credential input")
    credential = tmp_path / "credential.json"
    credential.write_text(json.dumps({"password": SENTINEL}), encoding="utf-8")
    os.chmod(credential, 0o644)
    with pytest.raises(ValueError, match="0600"):
        read_secure_file(credential)
    os.chmod(credential, 0o600)
    assert SENTINEL in read_secure_file(credential)


def test_cli_exposes_no_plaintext_argument_or_environment_secret_source() -> None:
    parsers = [_parser()]
    option_strings: set[str] = set()
    while parsers:
        parser = parsers.pop()
        for action in parser._actions:
            option_strings.update(action.option_strings)
            choices = getattr(action, "choices", None)
            if isinstance(choices, dict):
                parsers.extend(choices.values())
    retired = {"--password", "--password-" + "env", "--" + "hashes"}
    assert not retired & option_strings


def test_release_metadata_is_deterministic_and_binds_both_artifacts(
    tmp_path, monkeypatch
) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "gpowake-0.4.0-py3-none-any.whl").write_bytes(b"wheel")
    (dist / "gpowake-0.4.0.tar.gz").write_bytes(b"sdist")
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    first = generate(dist, "a" * 40)
    contents = tuple(path.read_bytes() for path in first)
    second = generate(dist, "a" * 40)
    assert contents == tuple(path.read_bytes() for path in second)
    sbom = json.loads(first[0].read_text(encoding="utf-8"))
    provenance = json.loads(first[1].read_text(encoding="utf-8"))
    assert sbom["spdxVersion"] == "SPDX-2.3"
    assert {item["name"] for item in provenance["subject"]} == {
        "gpowake-0.4.0-py3-none-any.whl",
        "gpowake-0.4.0.tar.gz",
    }
