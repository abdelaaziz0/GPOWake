from __future__ import annotations

import pytest

from gpowake.acl import (
    ADS_RIGHT_DS_WRITE_PROP,
    GPLINK_GUID,
    GPOPTIONS_GUID,
    access_check,
    capabilities_on_som,
)
from gpowake.gplink import parse_gplink, reorder_link, serialize_gplink
from gpowake.models import (
    AccessDecision,
    Ace,
    AceType,
    Capability,
    Principal,
    ScopeOfManagement,
    SecurityDescriptor,
    SomKind,
)

from conftest import ACTOR, DOMAIN_DN, DANGEROUS_DN, SAFE_DN


def test_microsoft_schema_guids_are_exact() -> None:
    assert GPLINK_GUID == "f30e3bbe-9ff0-11d1-b603-0000f80367c1"
    assert GPOPTIONS_GUID == "f30e3bbf-9ff0-11d1-b603-0000f80367c1"


def test_gplink_order_options_round_trip() -> None:
    raw = f"[LDAP://{DANGEROUS_DN};3][LDAP://{SAFE_DN};0]"
    links = parse_gplink(raw)
    assert [(link.order, link.disabled, link.enforced) for link in links] == [
        (1, True, True),
        (2, False, False),
    ]
    assert serialize_gplink(links) == raw


def test_gplink_rejects_partial_garbage() -> None:
    with pytest.raises(ValueError, match="malformed"):
        parse_gplink(f"junk[LDAP://{DANGEROUS_DN};0]")


def test_reorder_renumbers_all_links() -> None:
    links = parse_gplink(f"[LDAP://{DANGEROUS_DN};0][LDAP://{SAFE_DN};2]")
    reordered = reorder_link(links, SAFE_DN, 2, 1)
    assert [link.gpo_dn for link in reordered] == [SAFE_DN, DANGEROUS_DN]
    assert [link.order for link in reordered] == [1, 2]


def test_attribute_specific_acl_keeps_gplink_and_gpoptions_separate() -> None:
    principal = Principal(ACTOR, "actor", ())
    som = ScopeOfManagement(
        DOMAIN_DN,
        SomKind.DOMAIN,
        security_descriptor=SecurityDescriptor(
            (Ace(ACTOR, AceType.ALLOW, ADS_RIGHT_DS_WRITE_PROP, GPLINK_GUID),)
        ),
    )
    assert capabilities_on_som(principal, som) == {Capability.WRITE_GPLINK}
    assert Capability.WRITE_GPOPTIONS not in capabilities_on_som(principal, som)


def test_canonical_deny_wins() -> None:
    descriptor = SecurityDescriptor(
        (
            Ace(ACTOR, AceType.DENY, ADS_RIGHT_DS_WRITE_PROP, GPLINK_GUID),
            Ace(ACTOR, AceType.ALLOW, ADS_RIGHT_DS_WRITE_PROP, GPLINK_GUID),
        )
    )
    assert (
        access_check(descriptor, (ACTOR,), ADS_RIGHT_DS_WRITE_PROP, GPLINK_GUID)
        is AccessDecision.DENY
    )
    assert access_check(
        descriptor, (ACTOR,), ADS_RIGHT_DS_WRITE_PROP, GPOPTIONS_GUID
    ) is AccessDecision.DENY
