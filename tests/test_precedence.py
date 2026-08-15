from __future__ import annotations

from dataclasses import replace

from gpowake.models import Link, ScopeOfManagement, SomKind
from gpowake.precedence import LinkStatus, PolicyEngine

from conftest import DANGEROUS_DN, SAFE_DN, environment


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
