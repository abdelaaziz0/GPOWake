from __future__ import annotations

from dataclasses import replace

from gpowake.catalog import REGISTRY_CSE_GUID
from gpowake.models import (
    Link,
    RegistryOperation,
    ScopeOfManagement,
    Setting,
    SettingKind,
    SomKind,
)
from gpowake.precedence import LinkStatus, PolicyEngine
from gpowake.solver import CounterfactualSolver

from conftest import DANGEROUS_DN, SAFE_DN, environment, som_sd
from gpowake.acl import GPLINK_GUID


def test_same_scope_order_one_wins(base_environment) -> None:
    result = PolicyEngine(base_environment).evaluate(base_environment.targets[0])
    winner = result.winners[("PRIVILEGE_RIGHT", "sedebugprivilege")]
    assert winner.gpo.dn == SAFE_DN
    assert [item.link.order for item in result.processing_order] == [2, 1]


def test_descendant_normally_wins() -> None:
    env = environment(domain_links=(Link(DANGEROUS_DN),), ou_links=(Link(SAFE_DN),))
    result = PolicyEngine(env).evaluate(env.targets[0])
    assert result.winners[("PRIVILEGE_RIGHT", "sedebugprivilege")].gpo.dn == SAFE_DN


def test_enforced_ancestor_wins_over_descendant() -> None:
    env = environment(domain_links=(Link(DANGEROUS_DN, 2),), ou_links=(Link(SAFE_DN),))
    result = PolicyEngine(env).evaluate(env.targets[0])
    assert (
        result.winners[("PRIVILEGE_RIGHT", "sedebugprivilege")].gpo.dn == DANGEROUS_DN
    )


def test_block_inheritance_removes_normal_ancestor_but_not_enforced() -> None:
    normal = environment(domain_links=(Link(DANGEROUS_DN),), gp_options=1)
    normal_result = PolicyEngine(normal).evaluate(normal.targets[0])
    assert normal_result.links[0].status is LinkStatus.BLOCKED
    assert ("PRIVILEGE_RIGHT", "sedebugprivilege") not in normal_result.winners

    enforced = environment(domain_links=(Link(DANGEROUS_DN, 2),), gp_options=1)
    enforced_result = PolicyEngine(enforced).evaluate(enforced.targets[0])
    assert enforced_result.links[0].status is LinkStatus.APPLIES


def test_disabled_link_is_removed() -> None:
    env = environment(ou_links=(Link(DANGEROUS_DN, 1),))
    result = PolicyEngine(env).evaluate(env.targets[0])
    assert result.links[0].status is LinkStatus.DISABLED


def test_site_is_lower_than_domain_unless_site_link_is_enforced() -> None:
    site_dn = "CN=Paris,CN=Sites,CN=Configuration,DC=corp,DC=local"
    env = environment(domain_links=(Link(SAFE_DN),))
    env.soms[site_dn.casefold()] = ScopeOfManagement(
        site_dn, SomKind.SITE, links=(Link(DANGEROUS_DN),)
    )
    env.targets[0] = replace(env.targets[0], site_dn=site_dn)
    normal = PolicyEngine(env).evaluate(env.targets[0])
    assert normal.winners[("PRIVILEGE_RIGHT", "sedebugprivilege")].gpo.dn == SAFE_DN

    env.soms[site_dn.casefold()] = replace(
        env.soms[site_dn.casefold()], links=(Link(DANGEROUS_DN, 2),)
    )
    enforced = PolicyEngine(env).evaluate(env.targets[0])
    assert (
        enforced.winners[("PRIVILEGE_RIGHT", "sedebugprivilege")].gpo.dn == DANGEROUS_DN
    )


def test_unsupported_functionality_version_is_rejected() -> None:
    env = environment(ou_links=(Link(DANGEROUS_DN),), include_safe=False)
    danger = env.gpo(DANGEROUS_DN)
    env.gpos[DANGEROUS_DN.casefold()] = replace(danger, functionality_version=1)
    result = PolicyEngine(env).evaluate(env.targets[0])
    assert result.links[-1].status is LinkStatus.UNSUPPORTED


def _registry_setting(
    name: str,
    data: int | None,
    operation: RegistryOperation,
    *,
    dangerous: bool = False,
) -> Setting:
    key, _, value_name = name.rpartition("\\")
    return Setting(
        SettingKind.REGISTRY,
        name,
        None if data is None else {"type": 4, "data": data},
        dangerous=dangerous,
        required_extension=REGISTRY_CSE_GUID,
        registry_operation=operation,
        registry_key=key,
        registry_value_name=(
            value_name
            if operation
            in {
                RegistryOperation.SET_VALUE,
                RegistryOperation.SET_IF_ABSENT,
                RegistryOperation.DELETE_VALUE,
            }
            else None
        ),
    )


def test_registry_operations_replay_in_policy_order() -> None:
    name = "Software\\Policies\\Example\\Enabled"
    danger = environment(include_safe=False).gpo(DANGEROUS_DN)
    assert danger is not None
    settings = (
        _registry_setting(name, 0, RegistryOperation.SET_VALUE),
        _registry_setting(name, None, RegistryOperation.DELETE_VALUE),
        _registry_setting(name, 1, RegistryOperation.SET_IF_ABSENT),
        _registry_setting(name, 2, RegistryOperation.SET_IF_ABSENT),
    )
    danger = replace(
        danger,
        machine_extensions=(REGISTRY_CSE_GUID,),
        settings=settings,
    )
    env = environment(
        ou_links=(Link(DANGEROUS_DN),), danger=danger, include_safe=False
    )
    result = PolicyEngine(env).evaluate(env.targets[0])
    assert result.winners[settings[0].key].setting.value == {"type": 4, "data": 1}


def test_higher_precedence_registry_delete_can_be_reordered_behind_dangerous_set() -> None:
    name = (
        "System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\"
        "UseLogonCredential"
    )
    dangerous = _registry_setting(
        name, 1, RegistryOperation.SET_VALUE, dangerous=True
    )
    delete = _registry_setting(name, None, RegistryOperation.DELETE_VALUE)
    env = environment(
        ou_links=(Link(DANGEROUS_DN, 0, 2), Link(SAFE_DN, 0, 1)),
        ou_sd=som_sd(GPLINK_GUID),
    )
    danger = env.gpo(DANGEROUS_DN)
    safe = env.gpo(SAFE_DN)
    assert danger is not None and safe is not None
    env.gpos[danger.dn.casefold()] = replace(
        danger,
        machine_extensions=(REGISTRY_CSE_GUID,),
        settings=(dangerous,),
    )
    env.gpos[safe.dn.casefold()] = replace(
        safe,
        machine_extensions=(REGISTRY_CSE_GUID,),
        settings=(delete,),
    )

    result = PolicyEngine(env).evaluate(env.targets[0])
    assert dangerous.key not in result.winners
    findings = CounterfactualSolver(env).solve()
    assert len(findings) == 1
    assert findings[0].setting_name == name
    assert findings[0].reason.value == "OVERRIDDEN_SETTING"


def test_restricted_group_member_of_is_cumulative_not_last_writer() -> None:
    dangerous = Setting(
        SettingKind.RESTRICTED_GROUP,
        "S-1-5-21-1-2-3-1100/MemberOf",
        ("S-1-5-32-544",),
        dangerous=True,
    )
    benign = replace(dangerous, value=("S-1-5-32-545",), dangerous=False)
    env = environment(
        ou_links=(Link(DANGEROUS_DN, 0, 2), Link(SAFE_DN, 0, 1)),
    )
    danger = env.gpo(DANGEROUS_DN)
    safe = env.gpo(SAFE_DN)
    assert danger is not None and safe is not None
    env.gpos[danger.dn.casefold()] = replace(danger, settings=(dangerous,))
    env.gpos[safe.dn.casefold()] = replace(safe, settings=(benign,))

    result = PolicyEngine(env).evaluate(env.targets[0])
    assert result.winners[dangerous.key].setting.value == (
        "S-1-5-32-544",
        "S-1-5-32-545",
    )
    assert len(result.additive_contributors[dangerous.key]) == 2
    assert CounterfactualSolver(env).solve() == []
