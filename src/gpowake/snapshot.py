from __future__ import annotations

import json
from dataclasses import asdict, replace
from enum import Enum
from pathlib import Path
from typing import Any

from .catalog import setting_from_dict
from .gplink import parse_gplink, serialize_gplink
from .models import (
    Ace,
    AceType,
    AccessDecision,
    Environment,
    GPO,
    GptAccessObservation,
    GptAccessProbe,
    GptAccessSource,
    Principal,
    ScopeOfManagement,
    SecurityDescriptor,
    SomKind,
    SettingKind,
    Target,
    normalize_dn,
    normalize_sid,
    unique_normalized_sids,
)
from .parsers.gpttmpl import parse_gpttmpl_file
from .parsers.registry_pol import parse_registry_pol_file


SCHEMA_VERSION = 4
SUPPORTED_SCHEMA_VERSIONS = frozenset({1, 2, 3, SCHEMA_VERSION})
MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024
MAX_REFERENCED_POLICY_BYTES = 64 * 1024 * 1024
MAX_REFERENCED_POLICY_TOTAL_BYTES = 256 * 1024 * 1024
MAX_REFERENCED_POLICY_FILES = 4_096


def _integer(value: object, default: int = 0) -> int:
    if value is None:
        return default
    if type(value) is int:
        result = value
    if isinstance(value, str):
        result = int(value, 0)
    elif type(value) is not int:
        raise ValueError(f"expected JSON integer or integer string, got {value!r}")
    if result < 0:
        raise ValueError(f"integer cannot be negative: {value!r}")
    return result


def _optional_integer(value: object) -> int | None:
    if value is None:
        return None
    return _integer(value)


def _access_mask(value: object) -> int:
    mask = _integer(value)
    if not 0 <= mask <= 0xFFFFFFFF:
        raise ValueError(f"access mask is outside uint32 range: {value!r}")
    return mask


def _boolean(value: object, *, default: bool, field_name: str) -> bool:
    if value is None:
        return default
    if type(value) is not bool:
        raise ValueError(f"{field_name} must be a JSON boolean")
    return bool(value)


def _optional_boolean(value: object, *, field_name: str) -> bool | None:
    if value is None:
        return None
    return _boolean(value, default=False, field_name=field_name)


def _access_decision(value: object) -> AccessDecision:
    if isinstance(value, bool):
        return AccessDecision.ALLOW if value else AccessDecision.DENY
    return AccessDecision(str(value))


def _referenced_policy_path(snapshot_path: Path, value: object) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError("referenced policy path must be a non-empty string")
    base = snapshot_path.parent.resolve()
    candidate = (base / value).resolve()
    if candidate.parent != base and base not in candidate.parents:
        raise ValueError(
            f"referenced policy path escapes snapshot directory: {value!r}"
        )
    try:
        size = candidate.stat().st_size
    except OSError as exc:
        raise ValueError(f"referenced policy file is unreadable: {value!r}") from exc
    if size > MAX_REFERENCED_POLICY_BYTES:
        raise ValueError(
            f"referenced policy file exceeds {MAX_REFERENCED_POLICY_BYTES} bytes: {value!r}"
        )
    return candidate


def descriptor_from_dict(data: dict[str, Any] | None) -> SecurityDescriptor:
    if data is None:
        return SecurityDescriptor(
            collection_error="security descriptor was not collected"
        )
    return SecurityDescriptor(
        aces=tuple(
            Ace(
                trustee_sid=item["trustee_sid"],
                ace_type=AceType(item.get("ace_type", "ALLOW")),
                access_mask=_access_mask(item["access_mask"]),
                object_type=item.get("object_type"),
                inherited=_boolean(
                    item.get("inherited"), default=False, field_name="ACE.inherited"
                ),
                inherit_only=_boolean(
                    item.get("inherit_only"),
                    default=False,
                    field_name="ACE.inherit_only",
                ),
            )
            for item in data.get("aces", [])
        ),
        null_dacl=_boolean(
            data.get("null_dacl"), default=False, field_name="null_dacl"
        ),
        collection_error=data.get("collection_error"),
        owner_sid=data.get("owner_sid"),
        has_unsupported_ace=_boolean(
            data.get("has_unsupported_ace"),
            default=False,
            field_name="has_unsupported_ace",
        ),
        owner_implicit_rights_blocked=_boolean(
            data.get("owner_implicit_rights_blocked"),
            default=False,
            field_name="owner_implicit_rights_blocked",
        ),
        owner_implicit_rights_verified=_boolean(
            data.get("owner_implicit_rights_verified"),
            default=False,
            field_name="owner_implicit_rights_verified",
        ),
    )


def descriptor_to_dict(descriptor: SecurityDescriptor) -> dict[str, Any]:
    return {
        "null_dacl": descriptor.null_dacl,
        "collection_error": descriptor.collection_error,
        "owner_sid": descriptor.owner_sid,
        "has_unsupported_ace": descriptor.has_unsupported_ace,
        "owner_implicit_rights_blocked": descriptor.owner_implicit_rights_blocked,
        "owner_implicit_rights_verified": descriptor.owner_implicit_rights_verified,
        "aces": [
            {
                "trustee_sid": ace.trustee_sid,
                "ace_type": ace.ace_type.value,
                "access_mask": f"0x{ace.access_mask:08x}",
                "object_type": ace.object_type,
                "inherited": ace.inherited,
                "inherit_only": ace.inherit_only,
            }
            for ace in descriptor.aces
        ],
    }


def load_snapshot(path: str | Path) -> Environment:
    snapshot_path = Path(path)
    if snapshot_path.stat().st_size > MAX_SNAPSHOT_BYTES:
        raise ValueError(f"snapshot exceeds {MAX_SNAPSHOT_BYTES} bytes")
    data = json.loads(snapshot_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("snapshot root must be a JSON object")
    source_schema = data.get("schema_version")
    if type(source_schema) is not int or source_schema not in SUPPORTED_SCHEMA_VERSIONS:
        raise ValueError(
            f"unsupported snapshot schema {source_schema!r}; expected one of "
            f"{sorted(SUPPORTED_SCHEMA_VERSIONS)}"
        )

    referenced_paths: set[Path] = set()
    referenced_total = 0

    def referenced_policy(value: object) -> Path:
        nonlocal referenced_total
        candidate = _referenced_policy_path(snapshot_path, value)
        if candidate not in referenced_paths:
            if len(referenced_paths) >= MAX_REFERENCED_POLICY_FILES:
                raise ValueError(
                    f"snapshot exceeds the {MAX_REFERENCED_POLICY_FILES} referenced-policy "
                    "file budget"
                )
            referenced_total += candidate.stat().st_size
            if referenced_total > MAX_REFERENCED_POLICY_TOTAL_BYTES:
                raise ValueError(
                    "snapshot referenced-policy files exceed the aggregate "
                    f"{MAX_REFERENCED_POLICY_TOTAL_BYTES}-byte budget"
                )
            referenced_paths.add(candidate)
        return candidate

    soms: dict[str, ScopeOfManagement] = {}
    for item in data.get("soms", []):
        if "gp_link" in item:
            links = parse_gplink(item.get("gp_link"))
        else:
            from .models import Link

            links = tuple(
                Link(
                    link["gpo_dn"],
                    _integer(link.get("options")),
                    _integer(link.get("order"), index),
                )
                for index, link in enumerate(item.get("links", []), start=1)
            )
        som = ScopeOfManagement(
            dn=item["dn"],
            kind=SomKind(item["kind"]),
            parent_dn=item.get("parent_dn"),
            links=links,
            gp_options=_integer(item.get("gp_options")),
            security_descriptor=descriptor_from_dict(item.get("security_descriptor")),
        )
        som_key = normalize_dn(som.dn)
        if som_key in soms:
            raise ValueError(f"duplicate SOM DN in snapshot: {som.dn}")
        soms[som_key] = som

    gpos: dict[str, GPO] = {}
    for item in data.get("gpos", []):
        settings = [setting_from_dict(setting) for setting in item.get("settings", [])]
        for relative in item.get("gpt_tmpl_files", []):
            settings.extend(
                parse_gpttmpl_file(referenced_policy(relative))
            )
        for relative in item.get("registry_pol_files", []):
            settings.extend(
                parse_registry_pol_file(referenced_policy(relative))
            )
        extensions = item.get("machine_extensions")
        gpo = GPO(
            dn=item["dn"],
            guid=item["guid"],
            name=item.get("name") or item["guid"],
            flags=_integer(item.get("flags")),
            functionality_version=_optional_integer(
                item.get("functionality_version")
            ),
            file_sys_path=item.get("file_sys_path"),
            machine_extensions=tuple(extensions) if extensions is not None else None,
            settings=tuple(settings),
            security_descriptor=descriptor_from_dict(item.get("security_descriptor")),
            gpt_readable=_boolean(
                item.get("gpt_readable"),
                default=True,
                field_name="GPO.gpt_readable",
            ),
            collector_gpt_readable=_optional_boolean(
                item.get("collector_gpt_readable"),
                field_name="GPO.collector_gpt_readable",
            ),
            settings_complete=_boolean(
                item.get("settings_complete"),
                default=True,
                field_name="GPO.settings_complete",
            ),
            settings_uncertainty_reasons=tuple(
                str(reason)
                for reason in item.get("settings_uncertainty_reasons", [])
            ),
            incomplete_setting_kinds=tuple(
                SettingKind(kind)
                for kind in item.get("incomplete_setting_kinds", [])
            ),
            actor_gpt_write_decisions=tuple(
                (str(sid), _access_decision(decision))
                for sid, decision in item.get("actor_gpt_write_decisions", [])
            ),
            wmi_filter=item.get("wmi_filter"),
            wmi_result=_optional_boolean(
                item.get("wmi_result"), field_name="GPO.wmi_result"
            ),
            file_acl_writable_sids=tuple(item.get("file_acl_writable_sids", [])),
            version_number=_optional_integer(item.get("version_number")),
            gpt_version=_optional_integer(item.get("gpt_version")),
            usn_changed=_optional_integer(item.get("usn_changed")),
            gpt_hashes=tuple(
                (str(path), str(digest))
                for path, digest in item.get("gpt_hashes", [])
            ),
        )
        gpo_key = normalize_dn(gpo.dn)
        if gpo_key in gpos:
            raise ValueError(f"duplicate GPO DN in snapshot: {gpo.dn}")
        gpos[gpo_key] = gpo

    principals = [
        Principal(
            item["sid"],
            item.get("name", item["sid"]),
            unique_normalized_sids(item.get("token_sids", [])),
            token_incomplete=_boolean(
                item.get("token_incomplete"),
                default=False,
                field_name="Principal.token_incomplete",
            ),
        )
        for item in data.get("principals", [])
    ]
    targets = [
        Target(
            dn=item["dn"],
            name=item.get("name", item["dn"]),
            sid=item["sid"],
            som_dn=item["som_dn"],
            token_sids=unique_normalized_sids(item.get("token_sids", [])),
            site_dn=item.get("site_dn"),
            criticality=item.get("criticality", "NORMAL"),
            token_incomplete=_boolean(
                item.get("token_incomplete"),
                default=False,
                field_name="Target.token_incomplete",
            ),
            unresolved_token_sids=unique_normalized_sids(
                item.get("unresolved_token_sids", [])
            ),
            wmi_results=tuple(
                (
                    str(filter_id),
                    _boolean(
                        result,
                        default=False,
                        field_name="Target.wmi_results decision",
                    ),
                )
                for filter_id, result in item.get("wmi_results", [])
            ),
            gpt_read_observations=tuple(
                GptAccessObservation(
                    gpo_id=str(observation["gpo_id"]),
                    decision=_access_decision(observation["decision"]),
                    source=GptAccessSource(str(observation["source"])),
                    oracle=str(observation["oracle"]),
                    oracle_version=str(observation["oracle_version"]),
                    snapshot_sha256=str(observation["snapshot_sha256"]),
                    observed_at=str(observation["observed_at"]),
                    desired_access=_access_mask(observation["desired_access"]),
                    gpt_unc_path=str(observation["gpt_unc_path"]),
                    dc=str(observation["dc"]),
                    target_sid=str(observation["target_sid"]),
                    token_sids_sha256=str(observation["token_sids_sha256"]),
                    credential_principal=str(observation["credential_principal"]),
                    gpo_ad_version=_integer(observation["gpo_ad_version"]),
                    gpt_version=_integer(observation["gpt_version"]),
                    share_sd_sha256=(
                        str(observation["share_sd_sha256"])
                        if observation.get("share_sd_sha256") is not None
                        else None
                    ),
                    ntfs_sd_sha256=(
                        str(observation["ntfs_sd_sha256"])
                        if observation.get("ntfs_sd_sha256") is not None
                        else None
                    ),
                    probes=tuple(
                        GptAccessProbe(
                            relative_path=str(probe["relative_path"]),
                            status=str(probe["status"]),
                            sha256=(
                                str(probe["sha256"])
                                if probe.get("sha256") is not None
                                else None
                            ),
                        )
                        for probe in observation["probes"]
                    ),
                )
                for observation in item.get("gpt_read_observations", [])
                if source_schema >= 4
            ),
            gpt_read_decisions=tuple(
                (str(gpo_id), _access_decision(decision))
                for gpo_id, decision in item.get("gpt_read_decisions", [])
                if data.get("collected_at") is None
            ),
            site_resolution_error=item.get("site_resolution_error"),
        )
        for item in data.get("targets", [])
    ]
    environment = Environment(
        soms=soms,
        gpos=gpos,
        principals=principals,
        targets=targets,
        source_dc=data.get("source_dc"),
        warnings=list(data.get("warnings", [])),
        domain_sid=data.get("domain_sid"),
        forest_root_sid=data.get("forest_root_sid"),
        ldap_endpoint=data.get("ldap_endpoint"),
        smb_endpoint=data.get("smb_endpoint"),
        tls_verified=_optional_boolean(
            data.get("tls_verified"), field_name="tls_verified"
        ),
        collected_at=data.get("collected_at"),
    )
    if source_schema == 1:
        environment.warnings.append(
            "snapshot schema 1 was migrated in memory; target token uncertainty "
            "remains all-or-nothing until the environment is recollected"
        )
        if environment.collected_at is not None:
            environment.gpos = {
                key: replace(
                    gpo,
                    settings_complete=False,
                    settings_uncertainty_reasons=(
                        "schema-1 live snapshot cannot attest complete GPT settings",
                    ),
                )
                for key, gpo in environment.gpos.items()
            }
    if source_schema < 4 and any(
        item.get("gpt_read_observations") for item in data.get("targets", [])
    ):
        environment.warnings.append(
            "pre-schema-4 free-form GPT access observations were discarded; "
            "rerun the authenticated SMB oracle"
        )
    if data.get("collected_at") is not None and any(
        item.get("gpt_read_decisions") for item in data.get("targets", [])
    ):
        environment.warnings.append(
            "legacy unstructured GPT read decisions were discarded from the live snapshot"
        )
    validate_environment(environment)
    return environment


def validate_environment(environment: Environment) -> None:
    errors: list[str] = []
    principal_sids = [normalize_sid(item.sid) for item in environment.principals]
    if len(principal_sids) != len(set(principal_sids)):
        errors.append("principal SIDs are not unique")
    target_dns = [normalize_dn(item.dn) for item in environment.targets]
    target_sids = [normalize_sid(item.sid) for item in environment.targets]
    if len(target_dns) != len(set(target_dns)):
        errors.append("target DNs are not unique")
    if len(target_sids) != len(set(target_sids)):
        errors.append("target SIDs are not unique")
    for som in environment.soms.values():
        if som.parent_dn and environment.som(som.parent_dn) is None:
            errors.append(f"SOM {som.dn} refers to missing parent {som.parent_dn}")
        orders = [link.order for link in som.links]
        if orders != list(range(1, len(orders) + 1)):
            errors.append(f"SOM {som.dn} has non-contiguous link orders {orders}")
        for link in som.links:
            if environment.gpo(link.gpo_dn) is None:
                environment.warnings.append(
                    f"SOM {som.dn} links missing GPO {link.gpo_dn}"
                )
    for target in environment.targets:
        if environment.som(target.som_dn) is None:
            errors.append(f"target {target.name} refers to missing SOM {target.som_dn}")
        if target.site_dn and environment.som(target.site_dn) is None:
            errors.append(
                f"target {target.name} refers to missing site {target.site_dn}"
            )
        observation_ids = [
            gpo_id for gpo_id, _decision in target.gpt_read_decisions
        ] + [observation.gpo_id for observation in target.gpt_read_observations]
        canonical_observation_ids: list[str] = []
        for observation_id in observation_ids:
            matches = [
                gpo
                for gpo in environment.gpos.values()
                if gpo.matches_identifier(observation_id)
            ]
            if not matches:
                errors.append(
                    f"target {target.name} GPT observation refers to unknown GPO "
                    f"{observation_id}"
                )
                continue
            if len(matches) > 1:
                errors.append(
                    f"target {target.name} GPT observation is ambiguous: "
                    f"{observation_id}"
                )
                continue
            canonical_observation_ids.append(normalize_dn(matches[0].dn))
        if len(canonical_observation_ids) != len(set(canonical_observation_ids)):
            errors.append(
                f"target {target.name} has duplicate GPT access observations"
            )
        for observation in target.gpt_read_observations:
            matches = [
                gpo
                for gpo in environment.gpos.values()
                if gpo.matches_identifier(observation.gpo_id)
            ]
            if len(matches) != 1:
                continue
            gpo = matches[0]
            from .observations import validate_stored_observation

            try:
                validate_stored_observation(environment, target, gpo, observation)
            except ValueError as exc:
                errors.append(str(exc))
    if errors:
        raise ValueError("invalid snapshot:\n- " + "\n- ".join(errors))


def environment_to_dict(environment: Environment) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "source_dc": environment.source_dc,
        "warnings": environment.warnings,
        "domain_sid": environment.domain_sid,
        "forest_root_sid": environment.forest_root_sid,
        "ldap_endpoint": environment.ldap_endpoint,
        "smb_endpoint": environment.smb_endpoint,
        "tls_verified": environment.tls_verified,
        "collected_at": environment.collected_at,
        "soms": [
            {
                "dn": som.dn,
                "kind": som.kind.value,
                "parent_dn": som.parent_dn,
                "gp_link": serialize_gplink(som.links),
                "gp_options": som.gp_options,
                "security_descriptor": descriptor_to_dict(som.security_descriptor),
            }
            for som in environment.soms.values()
        ],
        "gpos": [
            {
                "dn": gpo.dn,
                "guid": gpo.guid,
                "name": gpo.name,
                "flags": gpo.flags,
                "functionality_version": gpo.functionality_version,
                "file_sys_path": gpo.file_sys_path,
                "machine_extensions": gpo.machine_extensions,
                "settings": [
                    {
                        "kind": setting.kind.value,
                        "name": setting.name,
                        "value": setting.value,
                        "dangerous": setting.dangerous,
                        "severity": setting.severity.value,
                        "rationale": setting.rationale,
                        "required_extension": setting.required_extension,
                        "risk_rule_id": setting.risk_rule_id,
                        "unexpected_trustees": setting.unexpected_trustees,
                    }
                    for setting in gpo.settings
                ],
                "security_descriptor": descriptor_to_dict(gpo.security_descriptor),
                "gpt_readable": gpo.gpt_readable,
                "collector_gpt_readable": gpo.collector_gpt_readable,
                "settings_complete": gpo.settings_complete,
                "settings_uncertainty_reasons": gpo.settings_uncertainty_reasons,
                "incomplete_setting_kinds": gpo.incomplete_setting_kinds,
                "actor_gpt_write_decisions": gpo.actor_gpt_write_decisions,
                "wmi_filter": gpo.wmi_filter,
                "wmi_result": gpo.wmi_result,
                "file_acl_writable_sids": gpo.file_acl_writable_sids,
                "version_number": gpo.version_number,
                "gpt_version": gpo.gpt_version,
                "usn_changed": gpo.usn_changed,
                "gpt_hashes": gpo.gpt_hashes,
            }
            for gpo in environment.gpos.values()
        ],
        "principals": [asdict(principal) for principal in environment.principals],
        "targets": [asdict(target) for target in environment.targets],
    }


def save_snapshot(environment: Environment, path: str | Path) -> None:
    Path(path).write_text(
        json.dumps(environment_to_dict(environment), indent=2, default=_json_default)
        + "\n",
        encoding="utf-8",
    )


def _json_default(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, tuple):
        return list(value)
    raise TypeError(f"cannot serialize {type(value).__name__}")
