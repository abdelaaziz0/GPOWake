from __future__ import annotations

import hashlib
import json
import re
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .models import (
    AccessDecision,
    Environment,
    GPO,
    GptAccessObservation,
    GptAccessProbe,
    GptAccessSource,
    Target,
    normalize_dn,
    normalize_sid,
)


OBSERVATION_SCHEMA_VERSION = 4
MAX_OBSERVATION_FILE_BYTES = 8 * 1024 * 1024
GPT_FILE_GENERIC_READ = 0x00120089
MAX_COLLECTION_OBSERVATION_SKEW = timedelta(minutes=30)
SMB_ORACLE_NAME = "gpowake-smb-effective-io"
SMB_IDENTITY_ATTESTATION = "PINNED_LDAP_BIND_OBJECT_SID_AND_TOKEN_GROUPS"
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}\Z")


def _text(value: object, field: str, *, max_length: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    result = value.strip()
    if len(result) > max_length:
        raise ValueError(f"{field} exceeds {max_length} characters")
    return result


def _digest(value: object, field: str, *, allow_none: bool = False) -> str | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{field} must be a 64-character hexadecimal SHA-256 digest")
    return value.casefold()


def token_sids_sha256(target: Target) -> str:
    """Stable hash of the exact target SID token captured in the snapshot."""

    encoded = "\n".join(sorted(target.all_sids)).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def machine_credential_matches(target: Target, principal: str) -> bool:
    """Require an exact LDAP-collected domain and machine-account identity."""

    if not all(
        (target.sam_account_name, target.dns_domain, target.netbios_domain)
    ):
        return False
    if "\\" in principal and "@" not in principal:
        domain, account = principal.split("\\", 1)
        expected_domain = target.netbios_domain
    elif "@" in principal and "\\" not in principal:
        account, domain = principal.rsplit("@", 1)
        expected_domain = target.dns_domain
    else:
        return False
    return (
        domain.casefold() == str(expected_domain).casefold()
        and account.casefold() == str(target.sam_account_name).casefold()
    )


def target_matches(target: Target, selector: str) -> bool:
    wanted = selector.casefold()
    return wanted in {
        target.name.casefold(),
        target.dn.casefold(),
        target.sid.casefold(),
    }


def gpo_matches(gpo: GPO, selector: str) -> bool:
    wanted = normalize_dn(selector)
    wanted_guid = wanted.strip("{}")
    return wanted in {normalize_dn(gpo.dn), normalize_dn(gpo.name)} or wanted_guid in {
        normalize_dn(gpo.guid).strip("{}"),
    }


def unique_match(items: list[Any], selector: str, predicate, kind: str):
    matches = [item for item in items if predicate(item, selector)]
    if not matches:
        raise ValueError(f"{kind} selector {selector!r} did not match the snapshot")
    if len(matches) != 1:
        raise ValueError(f"{kind} selector {selector!r} is ambiguous")
    return matches[0]


def _same_gpo_id(gpo: GPO, identifier: str) -> bool:
    return gpo.matches_identifier(identifier)


def _parse_time(value: object, field: str) -> tuple[str, datetime]:
    text = _text(value, field)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a UTC offset")
    return text, parsed.astimezone(timezone.utc)


def _domain_from_gpo(gpo: GPO) -> str:
    if gpo.file_sys_path:
        parts = [
            part
            for part in gpo.file_sys_path.replace("/", "\\").split("\\")
            if part
        ]
        if len(parts) >= 3 and parts[1].casefold() == "sysvol":
            return parts[2]
    labels = [part[3:] for part in gpo.dn.split(",") if part[:3].casefold() == "dc="]
    if not labels:
        raise ValueError(f"cannot derive DNS domain for GPO {gpo.name}")
    return ".".join(labels)


def expected_gpt_unc(dc: str, gpo: GPO) -> str:
    return f"\\\\{dc}\\SYSVOL\\{_domain_from_gpo(gpo)}\\Policies\\{gpo.guid}"


def _normalize_unc(value: str) -> tuple[str, ...]:
    parts = tuple(
        part.casefold()
        for part in value.replace("/", "\\").split("\\")
        if part
    )
    if len(parts) != 5 or parts[1] != "sysvol" or parts[3] != "policies":
        raise ValueError("gpt_unc_path must identify one GPO root on SYSVOL")
    return parts


def _relative_path(value: object, field: str) -> str:
    path = _text(value, field, max_length=1024).replace("/", "\\")
    parts = path.split("\\")
    if path.startswith("\\") or ":" in path or any(
        part in {"", ".", ".."} for part in parts
    ):
        raise ValueError(f"{field} must be a canonical relative GPT path")
    return "\\".join(parts)


def _probe_rows(value: object, field: str) -> tuple[GptAccessProbe, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{field} must be a non-empty JSON array")
    probes: list[GptAccessProbe] = []
    seen: set[str] = set()
    allowed = {"relative_path", "status", "sha256", "size"}
    for index, row in enumerate(value):
        item_field = f"{field}[{index}]"
        if not isinstance(row, dict) or set(row) != allowed:
            raise ValueError(
                f"{item_field} must contain exactly relative_path, status, sha256, size"
            )
        relative = _relative_path(row["relative_path"], f"{item_field}.relative_path")
        key = relative.casefold()
        if key in seen:
            raise ValueError(f"{field} contains duplicate path {relative!r}")
        seen.add(key)
        status = _text(row["status"], f"{item_field}.status", max_length=32)
        digest = _digest(row["sha256"], f"{item_field}.sha256", allow_none=True)
        size = row["size"]
        if size is not None and (type(size) is not int or size < 0):
            raise ValueError(f"{item_field}.size must be a non-negative integer or null")
        probes.append(GptAccessProbe(relative, status, digest, size))
    return tuple(probes)


def _validate_probe_binding(
    probes: tuple[GptAccessProbe, ...],
    decision: AccessDecision,
    gpo: GPO,
    field: str,
) -> None:
    expected = {
        path.replace("/", "\\").casefold(): digest.casefold()
        for path, digest in gpo.gpt_hashes
    }
    expected_sizes = {
        path.replace("/", "\\").casefold(): size
        for path, size in gpo.gpt_file_sizes
    }
    if not expected:
        raise ValueError(
            f"{field} cannot bind evidence because the snapshot has no GPT hashes"
        )
    actual = {probe.relative_path.casefold(): probe for probe in probes}
    if set(actual) != set(expected):
        raise ValueError(
            f"{field} must probe every and only snapshot-hashed GPT file"
        )
    if set(expected_sizes) != set(expected):
        raise ValueError(f"{field} cannot bind evidence without every GPT file size")
    for path, probe in actual.items():
        if probe.status == "READ_OK" and probe.sha256 != expected[path]:
            raise ValueError(
                f"{field} file hash differs from the bound snapshot for "
                f"{probe.relative_path}"
            )
        if probe.status == "READ_OK" and probe.size != expected_sizes[path]:
            raise ValueError(
                f"{field} file size differs from the bound snapshot for "
                f"{probe.relative_path}"
            )
    root = actual.get("gpt.ini")
    if root is None:
        raise ValueError(f"{field} lacks the global gpt.ini probe")
    expected_decision = (
        AccessDecision.DENY
        if root.status == "ACCESS_DENIED"
        else AccessDecision.ALLOW
        if all(probe.status == "READ_OK" for probe in probes)
        else AccessDecision.UNKNOWN
    )
    if decision is not expected_decision:
        raise ValueError(
            f"{field} aggregate decision does not match its per-file probes"
        )


def validate_stored_observation(
    environment: Environment,
    target: Target,
    gpo: GPO,
    observation: GptAccessObservation,
) -> None:
    """Revalidate imported evidence when a schema-5 snapshot is loaded."""

    field = f"{target.name}/{gpo.name} GPT access observation"
    if observation.desired_access != GPT_FILE_GENERIC_READ:
        raise ValueError(f"{field} has an unsupported desired-access mask")
    if environment.collected_at is None:
        raise ValueError(f"{field} requires snapshot collected_at")
    _collected_text, collected = _parse_time(
        environment.collected_at, "snapshot.collected_at"
    )
    _observed_text, observed = _parse_time(
        observation.observed_at, f"{field}.observed_at"
    )
    if abs(observed - collected) > MAX_COLLECTION_OBSERVATION_SKEW:
        raise ValueError(f"{field} is more than 30 minutes from collection")
    if observed > datetime.now(timezone.utc) + timedelta(minutes=5):
        raise ValueError(f"{field} is implausibly in the future")
    if environment.source_dc is None or (
        observation.dc.casefold() != environment.source_dc.casefold()
    ):
        raise ValueError(f"{field} DC does not match snapshot source_dc")
    if _normalize_unc(observation.gpt_unc_path) != _normalize_unc(
        expected_gpt_unc(observation.dc, gpo)
    ):
        raise ValueError(f"{field} UNC does not match the snapshot DC/GPO")
    if normalize_sid(observation.target_sid) != normalize_sid(target.sid):
        raise ValueError(f"{field} target SID does not match")
    if observation.token_sids_sha256.casefold() != token_sids_sha256(target):
        raise ValueError(f"{field} target token hash does not match")
    if not machine_credential_matches(target, observation.credential_principal):
        raise ValueError(f"{field} credential is not the target machine account")
    if normalize_sid(observation.authenticated_sid) != normalize_sid(target.sid):
        raise ValueError(f"{field} authenticated SID does not match the target")
    if observation.gpo_ad_version != gpo.version_number:
        raise ValueError(f"{field} AD version does not match")
    if observation.gpt_version != gpo.gpt_version:
        raise ValueError(f"{field} GPT version does not match")
    if observation.source is GptAccessSource.SMB_EFFECTIVE_IO:
        if (
            observation.oracle != SMB_ORACLE_NAME
            or observation.oracle_version != __version__
        ):
            raise ValueError(f"{field} identifies an unsupported SMB oracle")
        if observation.identity_attestation != SMB_IDENTITY_ATTESTATION:
            raise ValueError(f"{field} lacks pinned LDAP SID attestation")
        if (
            observation.share_sd_sha256 is not None
            or observation.ntfs_sd_sha256 is not None
        ):
            raise ValueError(f"{field} effective I/O cannot claim descriptor hashes")
    elif (
        observation.share_sd_sha256 is None
        or observation.ntfs_sd_sha256 is None
    ):
        raise ValueError(f"{field} AccessCheck lacks descriptor hashes")
    _validate_probe_binding(observation.probes, observation.decision, gpo, field)


def _observation_from_row(
    row: dict[str, object],
    index: int,
    environment: Environment,
    target: Target,
    gpo: GPO,
    snapshot_sha256: str,
) -> GptAccessObservation:
    field = f"observations[{index}]"
    try:
        decision = AccessDecision(row["decision"])
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field}.decision must be ALLOW, DENY, or UNKNOWN") from exc
    try:
        source = GptAccessSource(_text(row["source"], f"{field}.source"))
    except ValueError as exc:
        raise ValueError(
            f"{field}.source must be one of "
            + ", ".join(item.value for item in GptAccessSource)
        ) from exc
    oracle = _text(row["oracle"], f"{field}.oracle")
    oracle_version = _text(
        row["oracle_version"], f"{field}.oracle_version", max_length=64
    )
    observed_at, observed = _parse_time(row["observed_at"], f"{field}.observed_at")
    if environment.collected_at is None:
        raise ValueError(f"{field} cannot bind to a snapshot without collected_at")
    _collected_text, collected = _parse_time(
        environment.collected_at, "snapshot.collected_at"
    )
    if abs(observed - collected) > MAX_COLLECTION_OBSERVATION_SKEW:
        raise ValueError(
            f"{field}.observed_at is more than 30 minutes from snapshot collection"
        )
    if observed > datetime.now(timezone.utc) + timedelta(minutes=5):
        raise ValueError(f"{field}.observed_at is implausibly in the future")
    desired_access = row["desired_access"]
    if type(desired_access) is not int or desired_access != GPT_FILE_GENERIC_READ:
        raise ValueError(
            f"{field}.desired_access must be integer 0x{GPT_FILE_GENERIC_READ:08x}"
        )
    dc = _text(row["dc"], f"{field}.dc")
    if not environment.source_dc or dc.casefold() != environment.source_dc.casefold():
        raise ValueError(f"{field}.dc does not match the snapshot source DC")
    unc = _text(row["gpt_unc_path"], f"{field}.gpt_unc_path")
    if _normalize_unc(unc) != _normalize_unc(expected_gpt_unc(dc, gpo)):
        raise ValueError(f"{field}.gpt_unc_path does not match the snapshot DC/GPO")
    target_sid = _text(row["target_sid"], f"{field}.target_sid")
    if normalize_sid(target_sid) != normalize_sid(target.sid):
        raise ValueError(f"{field}.target_sid does not match the selected target")
    token_digest = _digest(
        row["token_sids_sha256"], f"{field}.token_sids_sha256"
    )
    if token_digest != token_sids_sha256(target):
        raise ValueError(
            f"{field}.token_sids_sha256 does not match the snapshot target token"
        )
    credential = _text(
        row["credential_principal"], f"{field}.credential_principal"
    )
    if not machine_credential_matches(target, credential):
        raise ValueError(
            f"{field}.credential_principal is not the selected target machine account"
        )
    authenticated_sid = _text(
        row["authenticated_sid"], f"{field}.authenticated_sid"
    )
    if normalize_sid(authenticated_sid) != normalize_sid(target.sid):
        raise ValueError(
            f"{field}.authenticated_sid does not match the selected target"
        )
    identity_attestation = _text(
        row["identity_attestation"], f"{field}.identity_attestation"
    )
    ad_version = row["gpo_ad_version"]
    gpt_version = row["gpt_version"]
    if type(ad_version) is not int or ad_version != gpo.version_number:
        raise ValueError(f"{field}.gpo_ad_version does not match the snapshot")
    if type(gpt_version) is not int or gpt_version != gpo.gpt_version:
        raise ValueError(f"{field}.gpt_version does not match the snapshot")
    share_hash = _digest(
        row["share_sd_sha256"], f"{field}.share_sd_sha256", allow_none=True
    )
    ntfs_hash = _digest(
        row["ntfs_sd_sha256"], f"{field}.ntfs_sd_sha256", allow_none=True
    )
    if source is GptAccessSource.SMB_EFFECTIVE_IO:
        if oracle != SMB_ORACLE_NAME or oracle_version != __version__:
            raise ValueError(
                f"{field} does not identify this supported SMB oracle version"
            )
        if identity_attestation != SMB_IDENTITY_ATTESTATION:
            raise ValueError(f"{field} lacks pinned LDAP SID attestation")
        if share_hash is not None or ntfs_hash is not None:
            raise ValueError(
                f"{field} effective-I/O evidence must not claim descriptor hashes"
            )
    elif share_hash is None or ntfs_hash is None:
        raise ValueError(
            f"{field} descriptor AccessCheck evidence requires share and NTFS hashes"
        )
    probes = _probe_rows(row["probes"], f"{field}.probes")
    _validate_probe_binding(probes, decision, gpo, field)
    return GptAccessObservation(
        gpo.dn,
        decision,
        source,
        oracle,
        oracle_version,
        snapshot_sha256,
        observed_at,
        desired_access,
        unc,
        dc,
        target.sid,
        token_digest,
        credential,
        authenticated_sid,
        identity_attestation,
        ad_version,
        gpt_version,
        share_hash,
        ntfs_hash,
        probes,
    )


def import_gpt_access_observations(
    environment: Environment,
    observation_path: str | Path,
    *,
    snapshot_sha256: str,
    replace_existing: bool = False,
) -> int:
    """Import snapshot-bound, machine-readable target/GPT authorization evidence."""

    path = Path(observation_path)
    if path.stat().st_size > MAX_OBSERVATION_FILE_BYTES:
        raise ValueError(
            f"observation file exceeds {MAX_OBSERVATION_FILE_BYTES} bytes"
        )
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("observation document root must be a JSON object")
    allowed_root = {
        "schema_version",
        "snapshot_sha256",
        "preflight",
        "observations",
    }
    if set(document) != allowed_root:
        unknown = set(document) - allowed_root
        missing = allowed_root - set(document)
        detail = [
            *(f"unknown {item}" for item in sorted(unknown)),
            *(f"missing {item}" for item in sorted(missing)),
        ]
        raise ValueError("invalid observation document fields: " + ", ".join(detail))
    schema_version = document["schema_version"]
    if type(schema_version) is not int or schema_version != OBSERVATION_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported observation schema {schema_version!r}; expected "
            f"{OBSERVATION_SCHEMA_VERSION}"
        )
    bound_digest = _digest(document["snapshot_sha256"], "snapshot_sha256")
    if bound_digest is None:
        raise ValueError("snapshot_sha256 cannot be null")
    if bound_digest != snapshot_sha256.casefold():
        raise ValueError("observation document is bound to a different snapshot")
    rows = document["observations"]
    if not isinstance(rows, list) or not rows:
        raise ValueError("observations must be a non-empty JSON array")
    preflight = document["preflight"]
    preflight_fields = {
        "selected_gpos",
        "total_files",
        "total_probes",
        "total_bytes",
        "max_total_files",
        "max_total_probes",
        "max_total_bytes",
    }
    if not isinstance(preflight, dict) or set(preflight) != preflight_fields:
        raise ValueError("preflight must contain exactly the aggregate oracle budgets")
    if any(type(preflight[field]) is not int or preflight[field] < 0 for field in preflight_fields):
        raise ValueError("preflight counters and limits must be non-negative integers")
    if preflight["total_files"] > preflight["max_total_files"]:
        raise ValueError("preflight file count exceeds its recorded limit")
    if preflight["total_probes"] > preflight["max_total_probes"]:
        raise ValueError("preflight probe count exceeds its recorded limit")
    if preflight["total_bytes"] > preflight["max_total_bytes"]:
        raise ValueError("preflight byte count exceeds its recorded limit")

    allowed_row = {
        "target",
        "gpo",
        "decision",
        "source",
        "oracle",
        "oracle_version",
        "observed_at",
        "desired_access",
        "gpt_unc_path",
        "dc",
        "target_sid",
        "token_sids_sha256",
        "credential_principal",
        "authenticated_sid",
        "identity_attestation",
        "gpo_ad_version",
        "gpt_version",
        "share_sd_sha256",
        "ntfs_sd_sha256",
        "probes",
    }
    targets = list(environment.targets)
    gpos = list(environment.gpos.values())
    resolved: list[tuple[Target, GPO, GptAccessObservation]] = []
    seen: set[tuple[str, str]] = set()
    for index, raw_row in enumerate(rows):
        if not isinstance(raw_row, dict):
            raise ValueError(f"observations[{index}] must be a JSON object")
        if set(raw_row) != allowed_row:
            unknown = set(raw_row) - allowed_row
            missing = allowed_row - set(raw_row)
            detail = [
                *(f"unknown {item}" for item in sorted(unknown)),
                *(f"missing {item}" for item in sorted(missing)),
            ]
            raise ValueError(
                f"invalid observations[{index}] fields: " + ", ".join(detail)
            )
        row = dict(raw_row)
        target_selector = _text(row["target"], f"observations[{index}].target")
        gpo_selector = _text(row["gpo"], f"observations[{index}].gpo")
        target = unique_match(targets, target_selector, target_matches, "target")
        gpo = unique_match(gpos, gpo_selector, gpo_matches, "GPO")
        key = (normalize_dn(target.dn), normalize_dn(gpo.dn))
        if key in seen:
            raise ValueError(
                f"duplicate target/GPO observation for {target.name} and {gpo.name}"
            )
        seen.add(key)
        resolved.append(
            (
                target,
                gpo,
                _observation_from_row(
                    row,
                    index,
                    environment,
                    target,
                    gpo,
                    bound_digest,
                ),
            )
        )

    bound_gpos = [gpo for _target, gpo, _item in resolved]
    expected_files = sum(len(gpo.gpt_hashes) for gpo in bound_gpos)
    expected_bytes = sum(
        size for gpo in bound_gpos for _path, size in gpo.gpt_file_sizes
    )
    if preflight["selected_gpos"] != len(bound_gpos):
        raise ValueError("preflight selected-GPO count does not match observations")
    if preflight["total_files"] != expected_files:
        raise ValueError("preflight file count does not match snapshot-bound GPOs")
    if preflight["total_probes"] != expected_files:
        raise ValueError("preflight probe count does not match snapshot-bound GPOs")
    if preflight["total_bytes"] != expected_bytes:
        raise ValueError("preflight byte count does not match snapshot-bound GPOs")

    by_target: dict[str, list[tuple[GPO, GptAccessObservation]]] = {}
    for target, gpo, observation in resolved:
        by_target.setdefault(normalize_dn(target.dn), []).append((gpo, observation))

    updated_targets: list[Target] = []
    for target in targets:
        additions = by_target.get(normalize_dn(target.dn), [])
        if not additions:
            updated_targets.append(target)
            continue
        replacing_gpos = [gpo for gpo, _observation in additions]
        existing_structured = list(target.gpt_read_observations)
        existing_legacy = list(target.gpt_read_decisions)
        conflicts = [
            gpo
            for gpo in replacing_gpos
            if any(_same_gpo_id(gpo, item.gpo_id) for item in existing_structured)
            or any(_same_gpo_id(gpo, item[0]) for item in existing_legacy)
        ]
        if conflicts and not replace_existing:
            raise ValueError(
                f"target {target.name} already has GPT access evidence for "
                + ", ".join(gpo.name for gpo in conflicts)
                + "; pass --replace-existing to replace it"
            )
        if replace_existing:
            existing_structured = [
                item
                for item in existing_structured
                if not any(_same_gpo_id(gpo, item.gpo_id) for gpo in replacing_gpos)
            ]
            existing_legacy = [
                item
                for item in existing_legacy
                if not any(_same_gpo_id(gpo, item[0]) for gpo in replacing_gpos)
            ]
        updated_targets.append(
            replace(
                target,
                gpt_read_observations=tuple(
                    [*existing_structured, *(item for _gpo, item in additions)]
                ),
                gpt_read_decisions=tuple(existing_legacy),
            )
        )

    environment.targets = updated_targets
    environment.warnings.append(
        f"imported {len(resolved)} target-specific GPT access observation(s) "
        f"from {path.name}"
    )
    from .snapshot import validate_environment

    validate_environment(environment)
    return len(resolved)
