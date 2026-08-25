from __future__ import annotations

import json
import hashlib
from dataclasses import replace

import pytest

from gpowake.cli import main
from gpowake.models import (
    AccessDecision,
    GptAccessObservation,
    GptAccessProbe,
    GptAccessSource,
    Link,
)
from gpowake.snapshot import load_snapshot, save_snapshot
from gpowake.solver import CounterfactualSolver
from gpowake.observations import GPT_FILE_GENERIC_READ, token_sids_sha256

from conftest import DANGEROUS_DN, SAFE_DN, environment, som_sd
from gpowake.acl import GPLINK_GUID


def test_snapshot_round_trip_and_cli_json(tmp_path) -> None:
    env = environment(
        ou_links=(Link(DANGEROUS_DN, 0, 2), Link(SAFE_DN, 0, 1)),
        ou_sd=som_sd(GPLINK_GUID),
    )
    env.targets[0] = replace(
        env.targets[0],
        unresolved_token_sids=("S-1-5-21-9-9-9-2500",),
        wmi_results=(("CN={FILTER},CN=SOM,CN=WMIPolicy", True),),
        gpt_read_decisions=((DANGEROUS_DN, AccessDecision.ALLOW),),
    )
    snapshot = tmp_path / "snapshot.json"
    report = tmp_path / "report.json"
    save_snapshot(env, snapshot)
    loaded = load_snapshot(snapshot)
    serialized = json.loads(snapshot.read_text())
    assert serialized["schema_version"] == 5
    assert len(loaded.gpos) == 2
    assert loaded.som(env.targets[0].som_dn).links[0].order == 1
    assert loaded.targets[0].unresolved_token_sids == (
        "S-1-5-21-9-9-9-2500",
    )
    assert loaded.targets[0].wmi_results[0][1] is True
    assert loaded.targets[0].gpt_read_decisions[0][1] is AccessDecision.ALLOW
    assert main(["scan", "--snapshot", str(snapshot), "--output", str(report)]) == 0
    document = json.loads(report.read_text())
    assert document["finding_count"] >= 1
    assert document["schema_version"] == 5
    assert "coverage_gaps" in document
    assert any(item["reason"] == "SAME_SCOPE_MASKED" for item in document["findings"])

    estimate = tmp_path / "estimate.json"
    assert (
        main(
            [
                "scan",
                "--snapshot",
                str(snapshot),
                "--estimate-only",
                "--output",
                str(estimate),
            ]
        )
        == 0
    )
    estimate_document = json.loads(estimate.read_text())
    assert estimate_document["candidate_evaluations_upper_bound"] >= 1

    jsonl = tmp_path / "report.jsonl"
    assert main(["scan", "--snapshot", str(snapshot), "--output", str(jsonl)]) == 0
    records = [json.loads(line) for line in jsonl.read_text().splitlines()]
    assert records[0]["record_type"] == "summary"
    finding_records = [item for item in records if item["record_type"] == "finding"]
    assert finding_records
    assert finding_records[0]["confidence"] == "LOW"
    assert finding_records[0]["severity"] == "CRITICAL"
    assert finding_records[0]["impact"]["rating"] == "CRITICAL"


def test_import_gpt_access_workflow_unblocks_live_snapshot(tmp_path) -> None:
    env = environment(
        ou_links=(Link(DANGEROUS_DN, 0, 2), Link(SAFE_DN, 0, 1)),
        ou_sd=som_sd(GPLINK_GUID),
    )
    env.collected_at = "2026-08-25T00:00:00+00:00"
    env.source_dc = "dc-lab-01.corp.local"
    for key, gpo in list(env.gpos.items()):
        env.gpos[key] = replace(
            gpo,
            functionality_version=2,
            collector_gpt_readable=True,
            file_sys_path=(
                f"\\\\dc-lab-01.corp.local\\SYSVOL\\corp.local\\Policies\\{gpo.guid}"
            ),
            version_number=7,
            gpt_version=7,
            gpt_hashes=(
                ("gpt.ini", "a" * 64),
                (
                    "Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf",
                    "d" * 64,
                ),
            ),
            gpt_file_sizes=(
                ("gpt.ini", 1),
                ("Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf", 1),
            ),
        )
    source = tmp_path / "live.json"
    observations = tmp_path / "gpt-access.json"
    merged = tmp_path / "merged.json"
    save_snapshot(env, source)
    observations.write_text(
        json.dumps(
            {
                "schema_version": 3,
                "snapshot_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "preflight": {
                    "selected_gpos": 2,
                    "total_files": 4,
                    "total_probes": 4,
                    "total_bytes": 4,
                    "max_total_files": 10,
                    "max_total_probes": 10,
                    "max_total_bytes": 10,
                },
                "observations": [
                    {
                        "target": env.targets[0].sid,
                        "gpo": gpo_dn,
                        "decision": "ALLOW",
                        "source": "WINDOWS_AUTHZ_ACCESSCHECK",
                        "oracle": "lab-authz-harness",
                        "oracle_version": "1.0.0",
                        "observed_at": "2026-08-25T00:05:00+00:00",
                        "desired_access": GPT_FILE_GENERIC_READ,
                        "gpt_unc_path": (
                            "\\\\dc-lab-01.corp.local\\SYSVOL\\corp.local\\Policies\\"
                            + env.gpo(gpo_dn).guid
                        ),
                        "dc": "dc-lab-01.corp.local",
                        "target_sid": env.targets[0].sid,
                        "token_sids_sha256": token_sids_sha256(env.targets[0]),
                        "credential_principal": "CORP\\SRV1$",
                        "authenticated_sid": env.targets[0].sid,
                        "identity_attestation": "LAB_WINDOWS_TOKEN_USER",
                        "gpo_ad_version": 7,
                        "gpt_version": 7,
                        "share_sd_sha256": "b" * 64,
                        "ntfs_sd_sha256": "c" * 64,
                        "probes": [
                            {
                                "relative_path": "gpt.ini",
                                "status": "READ_OK",
                                "sha256": "a" * 64,
                                "size": 1,
                            },
                            {
                                "relative_path": (
                                    "Machine\\Microsoft\\Windows NT\\SecEdit\\"
                                    "GptTmpl.inf"
                                ),
                                "status": "READ_OK",
                                "sha256": "d" * 64,
                                "size": 1,
                            }
                        ],
                    }
                    for gpo_dn in (DANGEROUS_DN, SAFE_DN)
                ],
            }
        )
    )
    assert (
        main(
            [
                "import-gpt-access",
                "--snapshot",
                str(source),
                "--observations",
                str(observations),
                "--output",
                str(merged),
            ]
        )
        == 0
    )
    loaded = load_snapshot(merged)
    assert len(loaded.targets[0].gpt_read_observations) == 2
    assert loaded.targets[0].gpt_read_observations[0].probes[0].status == "READ_OK"
    source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    assert loaded.targets[0].gpt_read_observations[0].snapshot_sha256 == source_digest
    findings = CounterfactualSolver(loaded).solve()
    assert findings
    assert findings[0].gpt_access_provenance[0].snapshot_sha256 == source_digest

    tampered = json.loads(merged.read_text())
    tampered["targets"][0]["gpt_read_observations"][0][
        "token_sids_sha256"
    ] = "f" * 64
    tampered_path = tmp_path / "tampered-observation.json"
    tampered_path.write_text(json.dumps(tampered))
    with pytest.raises(ValueError, match="target token hash does not match"):
        load_snapshot(tampered_path)

    wrong = json.loads(observations.read_text())
    wrong["snapshot_sha256"] = "0" * 64
    observations.write_text(json.dumps(wrong))
    rejected = tmp_path / "wrong-snapshot.json"
    assert (
        main(
            [
                "import-gpt-access",
                "--snapshot",
                str(source),
                "--observations",
                str(observations),
                "--output",
                str(rejected),
            ]
        )
        == 2
    )
    assert not rejected.exists()


def test_snapshot_rejects_string_booleans(tmp_path) -> None:
    snapshot = tmp_path / "bad.json"
    data = {
        "schema_version": 2,
        "soms": [],
        "gpos": [],
        "principals": [],
        "targets": [],
        "tls_verified": "false",
    }
    snapshot.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="tls_verified must be a JSON boolean"):
        load_snapshot(snapshot)


def test_snapshot_rejects_boolean_schema_version(tmp_path) -> None:
    snapshot = tmp_path / "bad-schema.json"
    snapshot.write_text(json.dumps({"schema_version": True}))
    with pytest.raises(ValueError, match="unsupported snapshot schema"):
        load_snapshot(snapshot)


def test_snapshot_rejects_gpt_observation_alias_duplicates(tmp_path) -> None:
    env = environment(include_safe=False)
    gpo = env.gpo(DANGEROUS_DN)
    assert gpo is not None
    env.targets[0] = replace(
        env.targets[0],
        gpt_read_decisions=((gpo.guid, AccessDecision.ALLOW),),
        gpt_read_observations=(
            GptAccessObservation(
                gpo.dn,
                AccessDecision.DENY,
                GptAccessSource.WINDOWS_AUTHZ_ACCESSCHECK,
                "lab-authz-harness",
                "1.0.0",
                "d" * 64,
                "2026-08-25T00:05:00+00:00",
                GPT_FILE_GENERIC_READ,
                f"\\\\dc-lab-01.corp.local\\SYSVOL\\corp.local\\Policies\\{gpo.guid}",
                "dc-lab-01.corp.local",
                env.targets[0].sid,
                token_sids_sha256(env.targets[0]),
                "CORP\\SRV1$",
                env.targets[0].sid,
                "LAB_WINDOWS_TOKEN_USER",
                7,
                7,
                "b" * 64,
                "c" * 64,
                (GptAccessProbe("gpt.ini", "ACCESS_DENIED"),),
            ),
        ),
    )
    snapshot = tmp_path / "duplicate-observation.json"
    save_snapshot(env, snapshot)
    with pytest.raises(ValueError, match="duplicate GPT access observations"):
        load_snapshot(snapshot)


def test_snapshot_policy_reference_cannot_escape_directory(tmp_path) -> None:
    outside = tmp_path.parent / "outside.inf"
    outside.write_text("[Privilege Rights]\n")
    snapshot = tmp_path / "escape.json"
    snapshot.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "soms": [],
                "gpos": [
                    {
                        "dn": "CN={A},CN=Policies,DC=corp,DC=local",
                        "guid": "{A}",
                        "gpt_tmpl_files": ["../outside.inf"],
                    }
                ],
                "principals": [],
                "targets": [],
            }
        )
    )
    with pytest.raises(ValueError, match="escapes snapshot directory"):
        load_snapshot(snapshot)


def test_snapshot_enforces_aggregate_referenced_policy_file_budget(
    tmp_path, monkeypatch
) -> None:
    first = tmp_path / "first.inf"
    second = tmp_path / "second.inf"
    first.write_text("[Privilege Rights]\n")
    second.write_text("[Privilege Rights]\n")
    snapshot = tmp_path / "references.json"
    snapshot.write_text(
        json.dumps(
            {
                "schema_version": 4,
                "soms": [],
                "gpos": [
                    {
                        "dn": "CN={A},CN=Policies,DC=corp,DC=local",
                        "guid": "{A}",
                        "gpt_tmpl_files": ["first.inf", "second.inf"],
                    }
                ],
                "principals": [],
                "targets": [],
            }
        )
    )
    monkeypatch.setattr("gpowake.snapshot.MAX_REFERENCED_POLICY_FILES", 1)
    with pytest.raises(ValueError, match="referenced-policy file budget"):
        load_snapshot(snapshot)
