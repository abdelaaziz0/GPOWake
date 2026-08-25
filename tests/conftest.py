from __future__ import annotations

import pytest

from gpowake.acl import (
    ADS_RIGHT_DS_CONTROL_ACCESS,
    ADS_RIGHT_DS_WRITE_PROP,
    APPLY_GROUP_POLICY_GUID,
    DIRECTORY_GENERIC_READ,
    FLAGS_GUID,
    GPLINK_GUID,
    WRITE_DAC,
)
from gpowake.catalog import SECURITY_CSE_GUID
from gpowake.models import (
    Ace,
    AceType,
    Environment,
    GPO,
    Link,
    Principal,
    ScopeOfManagement,
    SecurityDescriptor,
    Setting,
    SettingKind,
    Severity,
    SomKind,
    Target,
)


ACTOR = "S-1-5-21-1-2-3-1100"
TARGET = "S-1-5-21-1-2-3-2100"
AUTHENTICATED_USERS = "S-1-5-11"
DOMAIN_DN = "DC=corp,DC=local"
OU_DN = "OU=Servers,DC=corp,DC=local"
DANGEROUS_DN = (
    "CN={AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA},CN=Policies,CN=System,DC=corp,DC=local"
)
SAFE_DN = (
    "CN={BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB},CN=Policies,CN=System,DC=corp,DC=local"
)


def som_sd(*attribute_guids: str) -> SecurityDescriptor:
    return SecurityDescriptor(
        tuple(
            Ace(ACTOR, AceType.ALLOW, ADS_RIGHT_DS_WRITE_PROP, guid)
            for guid in attribute_guids
        )
    )


def gpo_sd(
    *, target_allowed: bool = True, write_dac: bool = False, write_flags: bool = False
) -> SecurityDescriptor:
    aces: list[Ace] = []
    if target_allowed:
        aces.extend(
            (
                Ace(AUTHENTICATED_USERS, AceType.ALLOW, DIRECTORY_GENERIC_READ),
                Ace(
                    AUTHENTICATED_USERS,
                    AceType.ALLOW,
                    ADS_RIGHT_DS_CONTROL_ACCESS,
                    APPLY_GROUP_POLICY_GUID,
                ),
            )
        )
    if write_dac:
        aces.append(Ace(ACTOR, AceType.ALLOW, WRITE_DAC))
    if write_flags:
        aces.append(Ace(ACTOR, AceType.ALLOW, ADS_RIGHT_DS_WRITE_PROP, FLAGS_GUID))
    return SecurityDescriptor(tuple(aces))


def dangerous_gpo(**changes) -> GPO:
    defaults = dict(
        dn=DANGEROUS_DN,
        guid="{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}",
        name="Legacy Dangerous Policy",
        machine_extensions=(SECURITY_CSE_GUID,),
        security_descriptor=gpo_sd(),
        settings=(
            Setting(
                SettingKind.PRIVILEGE_RIGHT,
                "SeDebugPrivilege",
                ("S-1-5-11",),
                dangerous=True,
                severity=Severity.CRITICAL,
                required_extension=SECURITY_CSE_GUID,
            ),
        ),
    )
    defaults.update(changes)
    return GPO(**defaults)


def safe_gpo() -> GPO:
    return GPO(
        dn=SAFE_DN,
        guid="{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}",
        name="Safe Winner",
        machine_extensions=(SECURITY_CSE_GUID,),
        security_descriptor=gpo_sd(),
        settings=(
            Setting(
                SettingKind.PRIVILEGE_RIGHT,
                "SeDebugPrivilege",
                ("S-1-5-32-544",),
                required_extension=SECURITY_CSE_GUID,
            ),
        ),
    )


def environment(
    *,
    domain_links: tuple[Link, ...] = (),
    ou_links: tuple[Link, ...] = (),
    domain_sd: SecurityDescriptor | None = None,
    ou_sd: SecurityDescriptor | None = None,
    gp_options: int = 0,
    danger: GPO | None = None,
    include_safe: bool = True,
) -> Environment:
    danger = danger or dangerous_gpo()
    gpos = {danger.dn: danger}
    if include_safe:
        safe = safe_gpo()
        gpos[safe.dn] = safe
    return Environment(
        soms={
            DOMAIN_DN: ScopeOfManagement(
                DOMAIN_DN,
                SomKind.DOMAIN,
                links=domain_links,
                security_descriptor=domain_sd or SecurityDescriptor(),
            ),
            OU_DN: ScopeOfManagement(
                OU_DN,
                SomKind.OU,
                parent_dn=DOMAIN_DN,
                links=ou_links,
                gp_options=gp_options,
                security_descriptor=ou_sd or SecurityDescriptor(),
            ),
        },
        gpos=gpos,
        principals=[Principal(ACTOR, "CORP\\helpdesk", (AUTHENTICATED_USERS,))],
        targets=[
            Target(
                "CN=SRV1," + OU_DN,
                "SRV1",
                TARGET,
                OU_DN,
                (AUTHENTICATED_USERS,),
                sam_account_name="SRV1$",
                dns_domain="corp.local",
                netbios_domain="CORP",
                criticality="TIER0",
            )
        ],
    )


@pytest.fixture
def base_environment() -> Environment:
    return environment(
        ou_links=(Link(DANGEROUS_DN, 0, 2), Link(SAFE_DN, 0, 1)),
        ou_sd=som_sd(GPLINK_GUID),
    )
