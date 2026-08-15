from __future__ import annotations

import json
from dataclasses import asdict
from enum import Enum
from pathlib import Path
from typing import Any

from .catalog import setting_from_dict
from .gplink import parse_gplink, serialize_gplink
from .models import (
    Ace,
    AceType,
    Environment,
    GPO,
    Principal,
    ScopeOfManagement,
    SecurityDescriptor,
    SomKind,
    Target,
    normalize_dn,
    unique_normalized_sids,
)
from .parsers.gpttmpl import parse_gpttmpl_file
from .parsers.registry_pol import parse_registry_pol_file


SCHEMA_VERSION = 1


def _integer(value: int | str | None, default: int = 0) -> int:
    if value is None:
        return default
    return int(value, 0) if isinstance(value, str) else int(value)


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
                access_mask=_integer(item["access_mask"]),
                object_type=item.get("object_type"),
                inherited=bool(item.get("inherited", False)),
            )
            for item in data.get("aces", [])
        ),
        null_dacl=bool(data.get("null_dacl", False)),
        collection_error=data.get("collection_error"),
    )


def descriptor_to_dict(descriptor: SecurityDescriptor) -> dict[str, Any]:
    return {
        "null_dacl": descriptor.null_dacl,
        "collection_error": descriptor.collection_error,
        "aces": [
            {
                "trustee_sid": ace.trustee_sid,
                "ace_type": ace.ace_type.value,
                "access_mask": f"0x{ace.access_mask:08x}",
                "object_type": ace.object_type,
                "inherited": ace.inherited,
            }
            for ace in descriptor.aces
        ],
    }


def load_snapshot(path: str | Path) -> Environment:
    snapshot_path = Path(path)
    data = json.loads(snapshot_path.read_text(encoding="utf-8"))
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            f"unsupported snapshot schema {data.get('schema_version')!r}; expected {SCHEMA_VERSION}"
        )

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
        soms[normalize_dn(som.dn)] = som

    gpos: dict[str, GPO] = {}
    for item in data.get("gpos", []):
        settings = [setting_from_dict(setting) for setting in item.get("settings", [])]
        for relative in item.get("gpt_tmpl_files", []):
            settings.extend(parse_gpttmpl_file(snapshot_path.parent / relative))
        for relative in item.get("registry_pol_files", []):
            settings.extend(parse_registry_pol_file(snapshot_path.parent / relative))
        extensions = item.get("machine_extensions")
        gpo = GPO(
            dn=item["dn"],
            guid=item["guid"],
            name=item.get("name") or item["guid"],
            flags=_integer(item.get("flags")),
            functionality_version=item.get("functionality_version"),
            file_sys_path=item.get("file_sys_path"),
            machine_extensions=tuple(extensions) if extensions is not None else None,
            settings=tuple(settings),
            security_descriptor=descriptor_from_dict(item.get("security_descriptor")),
            gpt_readable=bool(item.get("gpt_readable", True)),
            wmi_filter=item.get("wmi_filter"),
            wmi_result=item.get("wmi_result"),
            file_acl_writable_sids=tuple(item.get("file_acl_writable_sids", [])),
            version_number=item.get("version_number"),
            gpt_version=item.get("gpt_version"),
        )
        gpos[normalize_dn(gpo.dn)] = gpo

    principals = [
        Principal(
            item["sid"],
            item.get("name", item["sid"]),
            unique_normalized_sids(item.get("token_sids", [])),
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
    )
    validate_environment(environment)
    return environment


def validate_environment(environment: Environment) -> None:
    errors: list[str] = []
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
    if errors:
        raise ValueError("invalid snapshot:\n- " + "\n- ".join(errors))


def environment_to_dict(environment: Environment) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "source_dc": environment.source_dc,
        "warnings": environment.warnings,
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
                    }
                    for setting in gpo.settings
                ],
                "security_descriptor": descriptor_to_dict(gpo.security_descriptor),
                "gpt_readable": gpo.gpt_readable,
                "wmi_filter": gpo.wmi_filter,
                "wmi_result": gpo.wmi_result,
                "file_acl_writable_sids": gpo.file_acl_writable_sids,
                "version_number": gpo.version_number,
                "gpt_version": gpo.gpt_version,
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
