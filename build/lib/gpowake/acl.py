from __future__ import annotations

import uuid
from dataclasses import replace
from typing import Iterable

from .models import (
    Ace,
    AceType,
    Capability,
    GPO,
    Principal,
    ScopeOfManagement,
    SecurityDescriptor,
    normalize_sid,
)


# Active Directory access-mask bits.
ADS_RIGHT_DS_LIST = 0x00000004
ADS_RIGHT_DS_READ_PROP = 0x00000010
ADS_RIGHT_DS_WRITE_PROP = 0x00000020
ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
GENERIC_ALL = 0x10000000
GENERIC_WRITE = 0x40000000
GENERIC_READ = 0x80000000

# schemaIDGUID / controlAccessRight GUIDs used by the MVP.
GPLINK_GUID = "f30e3bbe-9ff0-11d1-b603-0000f80367c1"
GPOPTIONS_GUID = "f30e3bbf-9ff0-11d1-b603-0000f80367c1"
FLAGS_GUID = "bf967976-0de6-11d0-a285-00aa003049e2"
APPLY_GROUP_POLICY_GUID = "edacfd8f-ffb3-11d1-b41d-00a0c968f939"

DIRECTORY_GENERIC_READ = READ_CONTROL | ADS_RIGHT_DS_LIST | ADS_RIGHT_DS_READ_PROP
DIRECTORY_GENERIC_WRITE = READ_CONTROL | ADS_RIGHT_DS_WRITE_PROP
DIRECTORY_GENERIC_ALL = 0x000F01FF


def _norm_guid(value: str | None) -> str | None:
    return value.strip("{}").lower() if value else None


def _expanded_mask(mask: int) -> int:
    expanded = mask
    if mask & GENERIC_ALL:
        expanded |= DIRECTORY_GENERIC_ALL | WRITE_DAC
    if mask & GENERIC_WRITE:
        expanded |= DIRECTORY_GENERIC_WRITE
    if mask & GENERIC_READ:
        expanded |= DIRECTORY_GENERIC_READ
    return expanded


def access_check(
    descriptor: SecurityDescriptor,
    token_sids: Iterable[str],
    desired_access: int,
    object_type: str | None = None,
) -> bool:
    """Perform the ordered allow/deny portion of a Windows DACL access check."""
    if descriptor.collection_error:
        return False
    if descriptor.null_dacl:
        return True

    token = {normalize_sid(sid) for sid in token_sids}
    remaining = desired_access
    wanted_object = _norm_guid(object_type)
    for ace in descriptor.aces:
        if normalize_sid(ace.trustee_sid) not in token:
            continue
        ace_object = _norm_guid(ace.object_type)
        if ace_object is not None and ace_object != wanted_object:
            continue
        relevant = _expanded_mask(ace.access_mask) & remaining
        if not relevant:
            continue
        if ace.ace_type is AceType.DENY:
            return False
        remaining &= ~relevant
        if remaining == 0:
            return True
    return remaining == 0


def can_write_property(
    descriptor: SecurityDescriptor, token_sids: Iterable[str], attribute_guid: str
) -> bool:
    return access_check(descriptor, token_sids, ADS_RIGHT_DS_WRITE_PROP, attribute_guid)


def can_write_dacl(descriptor: SecurityDescriptor, token_sids: Iterable[str]) -> bool:
    return access_check(descriptor, token_sids, WRITE_DAC)


def can_read_gpo(descriptor: SecurityDescriptor, token_sids: Iterable[str]) -> bool:
    return access_check(descriptor, token_sids, DIRECTORY_GENERIC_READ)


def can_apply_gpo(descriptor: SecurityDescriptor, token_sids: Iterable[str]) -> bool:
    return access_check(
        descriptor, token_sids, ADS_RIGHT_DS_CONTROL_ACCESS, APPLY_GROUP_POLICY_GUID
    )


def capabilities_on_som(
    principal: Principal, som: ScopeOfManagement
) -> frozenset[Capability]:
    capabilities: set[Capability] = set()
    if can_write_property(som.security_descriptor, principal.all_sids, GPLINK_GUID):
        capabilities.add(Capability.WRITE_GPLINK)
    if can_write_property(som.security_descriptor, principal.all_sids, GPOPTIONS_GUID):
        capabilities.add(Capability.WRITE_GPOPTIONS)
    return frozenset(capabilities)


def capabilities_on_gpo(principal: Principal, gpo: GPO) -> frozenset[Capability]:
    capabilities: set[Capability] = set()
    if can_write_property(gpo.security_descriptor, principal.all_sids, FLAGS_GUID):
        capabilities.add(Capability.WRITE_GPO_CONTAINER)
    if can_write_dacl(gpo.security_descriptor, principal.all_sids):
        capabilities.add(Capability.WRITE_GPO_SECURITY)
    if principal.all_sids.intersection(
        normalize_sid(sid) for sid in gpo.file_acl_writable_sids
    ):
        capabilities.add(Capability.WRITE_GPO_FILESYSTEM)
    return frozenset(capabilities)


def grant_read_apply(descriptor: SecurityDescriptor, sid: str) -> SecurityDescriptor:
    """Return a descriptor with minimal allow ACEs appended for a target SID."""
    if descriptor.null_dacl:
        return descriptor
    aces = descriptor.aces + (
        Ace(sid, AceType.ALLOW, GENERIC_READ),
        Ace(sid, AceType.ALLOW, ADS_RIGHT_DS_CONTROL_ACCESS, APPLY_GROUP_POLICY_GUID),
    )
    return replace(descriptor, aces=aces)


def parse_security_descriptor(data: bytes | None) -> SecurityDescriptor:
    """Convert a self-relative AD security descriptor using impacket when present."""
    if not data:
        return SecurityDescriptor(
            collection_error="security descriptor was not returned"
        )
    try:
        from impacket.ldap.ldaptypes import (  # type: ignore[import-not-found]
            ACCESS_ALLOWED_ACE,
            ACCESS_ALLOWED_OBJECT_ACE,
            ACCESS_DENIED_ACE,
            ACCESS_DENIED_OBJECT_ACE,
            SR_SECURITY_DESCRIPTOR,
        )

        raw = SR_SECURITY_DESCRIPTOR(data=data)
        dacl = raw["Dacl"]
        if dacl is None:
            return SecurityDescriptor(null_dacl=True)
        allowed = {ACCESS_ALLOWED_ACE.ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE}
        denied = {ACCESS_DENIED_ACE.ACE_TYPE, ACCESS_DENIED_OBJECT_ACE.ACE_TYPE}
        parsed: list[Ace] = []
        for entry in dacl.aces:
            ace_type = int(entry["AceType"])
            if ace_type not in allowed | denied:
                continue
            body = entry["Ace"]
            object_type = None
            if ace_type in {
                ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE,
                ACCESS_DENIED_OBJECT_ACE.ACE_TYPE,
            }:
                raw_guid = body["ObjectType"]
                if raw_guid:
                    object_type = str(uuid.UUID(bytes_le=bytes(raw_guid)))
            parsed.append(
                Ace(
                    trustee_sid=body["Sid"].formatCanonical(),
                    ace_type=AceType.ALLOW if ace_type in allowed else AceType.DENY,
                    access_mask=int(body["Mask"]["Mask"]),
                    object_type=object_type,
                    inherited=bool(int(entry["AceFlags"]) & 0x10),
                )
            )
        return SecurityDescriptor(tuple(parsed))
    except Exception as exc:  # corrupted descriptors must fail closed
        return SecurityDescriptor(
            collection_error=f"could not parse security descriptor: {exc}"
        )
