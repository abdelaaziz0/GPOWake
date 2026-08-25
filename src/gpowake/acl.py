from __future__ import annotations

import uuid
from dataclasses import replace
from typing import Iterable

from .models import (
    AccessDecision,
    AccessEvidence,
    AccessResult,
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
WRITE_OWNER = 0x00080000
GENERIC_ALL = 0x10000000
GENERIC_WRITE = 0x40000000
GENERIC_READ = 0x80000000

# ACE header flags.
INHERIT_ONLY_ACE = 0x08
INHERITED_ACE = 0x10

# The owner of an object holds only these rights implicitly. WRITE_OWNER is
# deliberately absent: it requires an applicable ACE or SeTakeOwnershipPrivilege.
OWNER_IMPLICIT = READ_CONTROL | WRITE_DAC
OWNER_RIGHTS_SID = "S-1-3-4"

# schemaIDGUID / controlAccessRight GUIDs used by the MVP.
GPLINK_GUID = "f30e3bbe-9ff0-11d1-b603-0000f80367c1"
GPOPTIONS_GUID = "f30e3bbf-9ff0-11d1-b603-0000f80367c1"
FLAGS_GUID = "bf967976-0de6-11d0-a285-00aa003049e2"
APPLY_GROUP_POLICY_GUID = "edacfd8f-ffb3-11d1-b41d-00a0c968f939"

DIRECTORY_GENERIC_READ = READ_CONTROL | ADS_RIGHT_DS_LIST | ADS_RIGHT_DS_READ_PROP
DIRECTORY_GENERIC_WRITE = READ_CONTROL | ADS_RIGHT_DS_WRITE_PROP
DIRECTORY_GENERIC_ALL = 0x000F01FF


class UnsafeDaclRewriteError(ValueError):
    """The requested grant would require weakening an explicit deny/unknown ACE."""


def _norm_guid(value: str | None) -> str | None:
    return value.strip("{}").lower() if value else None


def _expanded_mask(mask: int) -> int:
    expanded = mask
    if mask & GENERIC_ALL:
        expanded |= DIRECTORY_GENERIC_ALL | WRITE_DAC | WRITE_OWNER
    if mask & GENERIC_WRITE:
        expanded |= DIRECTORY_GENERIC_WRITE
    if mask & GENERIC_READ:
        expanded |= DIRECTORY_GENERIC_READ
    return expanded


def evaluate_access(
    descriptor: SecurityDescriptor,
    token_sids: Iterable[str],
    desired_access: int,
    object_type: str | None = None,
    *,
    unresolved_token_sids: Iterable[str] = (),
) -> AccessResult:
    """Perform a tri-state ordered Windows DACL access check.

    The evaluated object's own DACL is walked in stored order. Beyond the plain
    allow/deny walk this models three things AD does that a naive scan misses:

    * INHERIT_ONLY_ACE entries are skipped -- they bind only to child objects,
      never to the object that carries them.
    * The object owner is granted implicit READ_CONTROL/WRITE_DAC
      unless an explicit OWNER RIGHTS (S-1-3-4) ACE constrains those rights.
    * ACE types GPOWake cannot interpret (callback/conditional) return UNKNOWN
      when they could affect the request. UNKNOWN is never treated as ALLOW.
    """
    if descriptor.collection_error:
        return AccessResult(
            AccessDecision.UNKNOWN,
            uncertainty_reasons=(descriptor.collection_error,),
        )
    if descriptor.null_dacl:
        return AccessResult(
            AccessDecision.ALLOW,
            (AccessEvidence("NULL_DACL", "null DACL grants requested access"),),
        )

    token = {normalize_sid(sid) for sid in token_sids}
    unresolved = {
        normalize_sid(sid) for sid in unresolved_token_sids
    } - token
    remaining = desired_access
    wanted_object = _norm_guid(object_type)
    evidence: list[AccessEvidence] = []

    owner = normalize_sid(descriptor.owner_sid) if descriptor.owner_sid else None
    is_owner = owner is not None and owner in token
    owner_rights = [
        (index, ace)
        for index, ace in enumerate(descriptor.aces)
        if ace.trustee_sid
        and normalize_sid(ace.trustee_sid) == OWNER_RIGHTS_SID
        and not ace.inherit_only
    ]
    if is_owner:
        for index, ace in owner_rights:
            ace_object = _norm_guid(ace.object_type)
            scope_matches = ace_object is None or ace_object == wanted_object
            mask_matches = ace.access_mask == 0 or bool(
                _expanded_mask(ace.access_mask) & remaining
            )
            if ace.ace_type is AceType.UNSUPPORTED and scope_matches and mask_matches:
                reason = (
                    f"unsupported OWNER RIGHTS ACE at DACL index {index} can affect "
                    "the requested access"
                )
                return AccessResult(
                    AccessDecision.UNKNOWN,
                    (
                        AccessEvidence(
                            "UNSUPPORTED_ACE",
                            reason,
                            index,
                            ace.trustee_sid,
                            ace.access_mask,
                            ace.object_type,
                            ace.inherited,
                        ),
                    ),
                    (reason,),
                )

    if (
        is_owner
        and not owner_rights
        and not descriptor.owner_implicit_rights_blocked
    ):
        implicit = remaining & OWNER_IMPLICIT
        if implicit and not descriptor.owner_implicit_rights_verified:
            reason = (
                "owner-implicit rights were not verified for this object's class "
                "and BlockOwnerImplicitRights context"
            )
            return AccessResult(
                AccessDecision.UNKNOWN,
                (
                    AccessEvidence(
                        "OWNER_UNVERIFIED",
                        reason,
                        trustee_sid=owner,
                        access_mask=implicit,
                    ),
                ),
                (reason,),
            )
        if implicit:
            evidence.append(
                AccessEvidence(
                    "OWNER",
                    f"object owner {owner} implicitly receives READ_CONTROL/WRITE_DAC",
                    trustee_sid=owner,
                    access_mask=implicit,
                )
            )
        remaining &= ~OWNER_IMPLICIT
        if remaining == 0:
            return AccessResult(AccessDecision.ALLOW, tuple(evidence))
    elif is_owner and descriptor.owner_implicit_rights_blocked and remaining & OWNER_IMPLICIT:
        evidence.append(
            AccessEvidence(
                "OWNER_BLOCKED",
                "BlockOwnerImplicitRights suppresses owner-implicit access",
                trustee_sid=owner,
                access_mask=remaining & OWNER_IMPLICIT,
            )
        )

    for index, ace in enumerate(descriptor.aces):
        if ace.inherit_only:
            continue
        trustee = normalize_sid(ace.trustee_sid) if ace.trustee_sid else None
        applies_to_owner = is_owner and trustee == OWNER_RIGHTS_SID
        applies_to_token = trustee is not None and trustee in token
        ace_object = _norm_guid(ace.object_type)
        if ace_object is not None and ace_object != wanted_object:
            continue
        membership_unknown = trustee is not None and trustee in unresolved
        if membership_unknown and remaining:
            relevant = (
                ace.ace_type is AceType.UNSUPPORTED and ace.access_mask == 0
            ) or bool(_expanded_mask(ace.access_mask) & remaining)
            if relevant:
                reason = (
                    f"membership of unresolved trustee {trustee} at DACL index "
                    f"{index} can affect the requested access"
                )
                item = AccessEvidence(
                    "UNRESOLVED_MEMBERSHIP",
                    reason,
                    index,
                    ace.trustee_sid,
                    ace.access_mask,
                    ace.object_type,
                    ace.inherited,
                )
                return AccessResult(
                    AccessDecision.UNKNOWN,
                    (*evidence, item),
                    (reason,),
                )
        if ace.ace_type is AceType.UNSUPPORTED and trustee is None and remaining:
            reason = (
                f"unsupported ACE at DACL index {index} has an undecodable trustee"
            )
            item = AccessEvidence(
                "UNSUPPORTED_ACE",
                reason,
                index,
                access_mask=ace.access_mask,
                object_type=ace.object_type,
                inherited=ace.inherited,
            )
            return AccessResult(
                AccessDecision.UNKNOWN,
                (*evidence, item),
                (reason,),
            )
        if not (applies_to_token or applies_to_owner):
            continue
        if ace.ace_type is AceType.UNSUPPORTED:
            relevant = ace.access_mask == 0 or bool(
                _expanded_mask(ace.access_mask) & remaining
            )
            if remaining and relevant:
                reason = (
                    f"unsupported ACE at DACL index {index} can affect the requested access"
                )
                item = AccessEvidence(
                    "UNSUPPORTED_ACE",
                    reason,
                    index,
                    ace.trustee_sid or None,
                    ace.access_mask,
                    ace.object_type,
                    ace.inherited,
                )
                return AccessResult(
                    AccessDecision.UNKNOWN,
                    (*evidence, item),
                    (reason,),
                )
            continue
        relevant_mask = _expanded_mask(ace.access_mask) & remaining
        if not relevant_mask:
            continue
        item = AccessEvidence(
            "ACE",
            f"{ace.ace_type.value} ACE at DACL index {index}",
            index,
            ace.trustee_sid,
            ace.access_mask,
            ace.object_type,
            ace.inherited,
        )
        if ace.ace_type is AceType.DENY:
            return AccessResult(AccessDecision.DENY, (*evidence, item))
        evidence.append(item)
        remaining &= ~relevant_mask
        if remaining == 0:
            return AccessResult(AccessDecision.ALLOW, tuple(evidence))
    return AccessResult(
        AccessDecision.DENY,
        (
            *evidence,
            AccessEvidence(
                "DACL_EXHAUSTED",
                f"DACL did not grant remaining mask 0x{remaining:08x}",
                access_mask=remaining,
                object_type=object_type,
            ),
        ),
    )


def access_check(
    descriptor: SecurityDescriptor,
    token_sids: Iterable[str],
    desired_access: int,
    object_type: str | None = None,
    *,
    unresolved_token_sids: Iterable[str] = (),
) -> AccessDecision:
    return evaluate_access(
        descriptor,
        token_sids,
        desired_access,
        object_type,
        unresolved_token_sids=unresolved_token_sids,
    ).decision


def evaluate_write_property(
    descriptor: SecurityDescriptor, token_sids: Iterable[str], attribute_guid: str
) -> AccessResult:
    return evaluate_access(
        descriptor, token_sids, ADS_RIGHT_DS_WRITE_PROP, attribute_guid
    )


def evaluate_write_dacl(
    descriptor: SecurityDescriptor, token_sids: Iterable[str]
) -> AccessResult:
    return evaluate_access(descriptor, token_sids, WRITE_DAC)


def evaluate_read_gpo(
    descriptor: SecurityDescriptor,
    token_sids: Iterable[str],
    *,
    unresolved_token_sids: Iterable[str] = (),
) -> AccessResult:
    return evaluate_access(
        descriptor,
        token_sids,
        DIRECTORY_GENERIC_READ,
        unresolved_token_sids=unresolved_token_sids,
    )


def evaluate_apply_gpo(
    descriptor: SecurityDescriptor,
    token_sids: Iterable[str],
    *,
    unresolved_token_sids: Iterable[str] = (),
) -> AccessResult:
    return evaluate_access(
        descriptor,
        token_sids,
        ADS_RIGHT_DS_CONTROL_ACCESS,
        APPLY_GROUP_POLICY_GUID,
        unresolved_token_sids=unresolved_token_sids,
    )


def can_write_property(
    descriptor: SecurityDescriptor, token_sids: Iterable[str], attribute_guid: str
) -> bool:
    return evaluate_write_property(descriptor, token_sids, attribute_guid).decision is AccessDecision.ALLOW


def can_write_dacl(
    descriptor: SecurityDescriptor, token_sids: Iterable[str]
) -> bool:
    return evaluate_write_dacl(descriptor, token_sids).decision is AccessDecision.ALLOW


def can_read_gpo(
    descriptor: SecurityDescriptor,
    token_sids: Iterable[str],
    *,
    unresolved_token_sids: Iterable[str] = (),
) -> bool:
    return evaluate_read_gpo(
        descriptor,
        token_sids,
        unresolved_token_sids=unresolved_token_sids,
    ).decision is AccessDecision.ALLOW


def can_apply_gpo(
    descriptor: SecurityDescriptor,
    token_sids: Iterable[str],
    *,
    unresolved_token_sids: Iterable[str] = (),
) -> bool:
    return evaluate_apply_gpo(
        descriptor,
        token_sids,
        unresolved_token_sids=unresolved_token_sids,
    ).decision is AccessDecision.ALLOW


def capabilities_on_som(
    principal: Principal, som: ScopeOfManagement
) -> frozenset[Capability]:
    if principal.token_incomplete:
        return frozenset()
    capabilities: set[Capability] = set()
    descriptor = som.security_descriptor
    if can_write_property(descriptor, principal.all_sids, GPLINK_GUID):
        capabilities.add(Capability.WRITE_GPLINK)
    if can_write_property(descriptor, principal.all_sids, GPOPTIONS_GUID):
        capabilities.add(Capability.WRITE_GPOPTIONS)
    # WRITE_DAC (explicit or owner-implicit) lets the actor rewrite the SOM DACL
    # to grant itself gPLink, so it is a two-step enabler for link changes.
    if can_write_dacl(descriptor, principal.all_sids):
        capabilities.add(Capability.WRITE_SOM_SECURITY)
    return frozenset(capabilities)


def capabilities_on_gpo(principal: Principal, gpo: GPO) -> frozenset[Capability]:
    if principal.token_incomplete:
        return frozenset()
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


def rewrite_dacl_grant(
    descriptor: SecurityDescriptor,
    sid: str,
    token_sids: Iterable[str],
    grants: Iterable[tuple[int, str | None]],
) -> tuple[SecurityDescriptor, tuple[Ace, ...], tuple[Ace, ...]]:
    """Build a conservative, additive DACL grant.

    The rewrite never weakens or deletes an explicit deny/unsupported ACE. If
    one blocks the requested grant, the operation is refused because narrowing
    a generic mask can expose unrelated rights. Inherited denies remain safe:
    a new canonical explicit allow consumes only the requested bits first.
    """

    if descriptor.null_dacl:
        return descriptor, (), ()
    token = {normalize_sid(value) for value in token_sids}
    token.add(normalize_sid(sid))
    owner = normalize_sid(descriptor.owner_sid) if descriptor.owner_sid else None
    is_owner = owner is not None and owner in token
    requested = tuple(grants)
    added: list[Ace] = []
    for ace in descriptor.aces:
        trustee = normalize_sid(ace.trustee_sid) if ace.trustee_sid else None
        undecodable = ace.ace_type is AceType.UNSUPPORTED and trustee is None
        if undecodable and not ace.inherited and not ace.inherit_only:
            raise UnsafeDaclRewriteError(
                "refusing additive rewrite across an unsupported explicit ACE "
                "with an undecodable trustee"
            )
        applies = trustee in token or (is_owner and trustee == OWNER_RIGHTS_SID)
        if ace.inherited or ace.inherit_only or not applies:
            continue
        for desired, object_type in requested:
            ace_object = _norm_guid(ace.object_type)
            wanted_object = _norm_guid(object_type)
            if ace_object is not None and ace_object != wanted_object:
                continue
            relevant = (
                ace.ace_type is AceType.UNSUPPORTED and ace.access_mask == 0
            ) or bool(_expanded_mask(ace.access_mask) & desired)
            if relevant and ace.ace_type in {AceType.DENY, AceType.UNSUPPORTED}:
                raise UnsafeDaclRewriteError(
                    "refusing to weaken explicit "
                    f"{ace.ace_type.value} ACE for {ace.trustee_sid or 'unknown trustee'}"
                )
    for mask, object_type in requested:
        item = Ace(sid, AceType.ALLOW, mask, object_type)
        added.append(item)
    # Preserve every existing ACE and its relative order. Re-canonicalizing an
    # inherited/noncanonical descriptor can change unrelated principals'
    # effective rights. New explicit allows are inserted immediately before
    # the inherited portion, which is sufficient to consume the narrow grant
    # before any inherited deny without moving pre-existing entries.
    insertion = next(
        (
            index
            for index, ace in enumerate(descriptor.aces)
            if ace.inherited
        ),
        len(descriptor.aces),
    )
    rewritten_aces = (
        descriptor.aces[:insertion]
        + tuple(added)
        + descriptor.aces[insertion:]
    )
    rewritten = replace(descriptor, aces=rewritten_aces)
    return rewritten, (), tuple(added)


def rewrite_dacl_explicit_blockers(
    descriptor: SecurityDescriptor,
    sid: str,
    token_sids: Iterable[str],
    grants: Iterable[tuple[int, str | None]],
) -> tuple[SecurityDescriptor, tuple[Ace, ...], tuple[Ace, ...]]:
    """Remove applicable explicit blockers, then add narrow explicit grants.

    This does not model DACL protection or removal of inherited ACEs. Removing
    an entire generic/callback explicit ACE can change unrelated rights for
    every member of its trustee; callers must expose the returned removals as
    collateral. Inherited ACEs are preserved and explicit grants precede them.
    """

    if descriptor.null_dacl:
        return descriptor, (), ()
    token = {normalize_sid(value) for value in token_sids}
    token.add(normalize_sid(sid))
    owner = normalize_sid(descriptor.owner_sid) if descriptor.owner_sid else None
    is_owner = owner is not None and owner in token
    requested = tuple(grants)
    removed: list[Ace] = []
    retained: list[Ace] = []
    for ace in descriptor.aces:
        trustee = normalize_sid(ace.trustee_sid) if ace.trustee_sid else None
        applies = trustee in token or (is_owner and trustee == OWNER_RIGHTS_SID)
        undecodable = ace.ace_type is AceType.UNSUPPORTED and trustee is None
        blocks = False
        if not ace.inherited and not ace.inherit_only and (applies or undecodable):
            for desired, object_type in requested:
                ace_object = _norm_guid(ace.object_type)
                wanted_object = _norm_guid(object_type)
                if ace_object is not None and ace_object != wanted_object:
                    continue
                relevant = (
                    ace.ace_type is AceType.UNSUPPORTED and ace.access_mask == 0
                ) or bool(_expanded_mask(ace.access_mask) & desired)
                if relevant and ace.ace_type in {AceType.DENY, AceType.UNSUPPORTED}:
                    blocks = True
                    break
        if blocks:
            removed.append(ace)
        else:
            retained.append(ace)
    added = tuple(Ace(sid, AceType.ALLOW, mask, object_type) for mask, object_type in requested)
    insertion = next(
        (index for index, ace in enumerate(retained) if ace.inherited),
        len(retained),
    )
    rewritten_aces = tuple(retained[:insertion]) + added + tuple(retained[insertion:])
    rewritten = replace(
        descriptor,
        aces=rewritten_aces,
        has_unsupported_ace=any(
            ace.ace_type is AceType.UNSUPPORTED for ace in rewritten_aces
        ),
    )
    return rewritten, tuple(removed), added


def rewrite_read_apply_explicit_blockers(
    descriptor: SecurityDescriptor, sid: str, token_sids: Iterable[str] = ()
) -> tuple[SecurityDescriptor, tuple[Ace, ...], tuple[Ace, ...]]:
    return rewrite_dacl_explicit_blockers(
        descriptor,
        sid,
        token_sids,
        (
            (DIRECTORY_GENERIC_READ, None),
            (ADS_RIGHT_DS_CONTROL_ACCESS, APPLY_GROUP_POLICY_GUID),
        ),
    )


def rewrite_write_gplink_explicit_blockers(
    descriptor: SecurityDescriptor, sid: str, token_sids: Iterable[str] = ()
) -> tuple[SecurityDescriptor, tuple[Ace, ...], tuple[Ace, ...]]:
    return rewrite_dacl_explicit_blockers(
        descriptor,
        sid,
        token_sids,
        ((ADS_RIGHT_DS_WRITE_PROP, GPLINK_GUID),),
    )


def rewrite_read_apply(
    descriptor: SecurityDescriptor, sid: str, token_sids: Iterable[str] = ()
) -> tuple[SecurityDescriptor, tuple[Ace, ...], tuple[Ace, ...]]:
    return rewrite_dacl_grant(
        descriptor,
        sid,
        token_sids,
        (
            (DIRECTORY_GENERIC_READ, None),
            (ADS_RIGHT_DS_CONTROL_ACCESS, APPLY_GROUP_POLICY_GUID),
        ),
    )


def grant_read_apply(
    descriptor: SecurityDescriptor, sid: str, token_sids: Iterable[str] = ()
) -> SecurityDescriptor:
    return rewrite_read_apply(descriptor, sid, token_sids)[0]


def rewrite_write_gplink(
    descriptor: SecurityDescriptor, sid: str, token_sids: Iterable[str] = ()
) -> tuple[SecurityDescriptor, tuple[Ace, ...], tuple[Ace, ...]]:
    """Return a descriptor granting the SID WriteProperty on gPLink only.

    Models the effect of an actor using WRITE_DAC on a SOM to give itself the
    link-management rights it lacks, as the first half of a two-action path.
    """
    return rewrite_dacl_grant(
        descriptor,
        sid,
        token_sids,
        (
            (ADS_RIGHT_DS_WRITE_PROP, GPLINK_GUID),
        ),
    )


def grant_write_gplink(
    descriptor: SecurityDescriptor, sid: str, token_sids: Iterable[str] = ()
) -> SecurityDescriptor:
    return rewrite_write_gplink(descriptor, sid, token_sids)[0]


def parse_security_descriptor(
    data: bytes | None, *, owner_implicit_rights_verified: bool = False
) -> SecurityDescriptor:
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
        owner_sid = None
        owner = raw["OwnerSid"]
        if owner is not None:
            try:
                owner_sid = owner.formatCanonical()
            except Exception:
                owner_sid = None
        dacl = raw["Dacl"]
        if dacl is None:
            return SecurityDescriptor(
                null_dacl=True,
                owner_sid=owner_sid,
                owner_implicit_rights_verified=owner_implicit_rights_verified,
            )
        allowed = {ACCESS_ALLOWED_ACE.ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE}
        denied = {ACCESS_DENIED_ACE.ACE_TYPE, ACCESS_DENIED_OBJECT_ACE.ACE_TYPE}
        object_types = {
            ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE,
            ACCESS_DENIED_OBJECT_ACE.ACE_TYPE,
        }
        parsed: list[Ace] = []
        has_unsupported = False
        for entry in dacl.aces:
            ace_type = int(entry["AceType"])
            flags = int(entry["AceFlags"])
            inherit_only = bool(flags & INHERIT_ONLY_ACE)
            inherited = bool(flags & INHERITED_ACE)
            if ace_type not in allowed | denied:
                # Retain the ACE in DACL order so the access check can fail
                # closed instead of dropping a potentially relevant deny.
                has_unsupported = True
                trustee = None
                mask = 0
                object_type = None
                try:
                    body = entry["Ace"]
                    trustee = body["Sid"].formatCanonical()
                    mask = int(body["Mask"]["Mask"])
                    raw_guid = body["ObjectType"]
                    if raw_guid:
                        object_type = str(uuid.UUID(bytes_le=bytes(raw_guid)))
                except Exception:
                    pass
                parsed.append(
                    Ace(
                        trustee_sid=trustee or "",
                        ace_type=AceType.UNSUPPORTED,
                        access_mask=mask,
                        object_type=object_type,
                        inherited=inherited,
                        inherit_only=inherit_only,
                    )
                )
                continue
            body = entry["Ace"]
            object_type = None
            if ace_type in object_types:
                raw_guid = body["ObjectType"]
                if raw_guid:
                    object_type = str(uuid.UUID(bytes_le=bytes(raw_guid)))
            parsed.append(
                Ace(
                    trustee_sid=body["Sid"].formatCanonical(),
                    ace_type=AceType.ALLOW if ace_type in allowed else AceType.DENY,
                    access_mask=int(body["Mask"]["Mask"]),
                    object_type=object_type,
                    inherited=inherited,
                    inherit_only=inherit_only,
                )
            )
        return SecurityDescriptor(
            tuple(parsed),
            owner_sid=owner_sid,
            has_unsupported_ace=has_unsupported,
            owner_implicit_rights_verified=owner_implicit_rights_verified,
        )
    except Exception as exc:  # corrupted descriptors must fail closed
        return SecurityDescriptor(
            collection_error=f"could not parse security descriptor: {exc}"
        )
