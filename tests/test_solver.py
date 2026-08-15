from __future__ import annotations

from gpowake.acl import GPLINK_GUID, GPOPTIONS_GUID
from gpowake.models import ActionType, DormancyReason, Link
from gpowake.solver import CounterfactualSolver

from conftest import DANGEROUS_DN, SAFE_DN, dangerous_gpo, environment, gpo_sd, som_sd


def test_reorder_is_one_action_activation(base_environment) -> None:
    findings = CounterfactualSolver(base_environment).solve()
    reorder = next(
        item for item in findings if item.actions[0].type is ActionType.REORDER_LINK
    )
    assert reorder.reason is DormancyReason.SAME_SCOPE_MASKED
    assert reorder.current_winner == "Safe Winner"
    assert reorder.targets == ["SRV1"]
    assert reorder.requires_gpo_edit is False


def test_clear_block_inheritance_uses_gpoptions_not_gplink() -> None:
    env = environment(
        domain_links=(Link(DANGEROUS_DN),),
        gp_options=1,
        ou_sd=som_sd(GPOPTIONS_GUID),
        include_safe=False,
    )
    findings = CounterfactualSolver(env).solve()
    assert len(findings) == 1
    assert findings[0].reason is DormancyReason.BLOCKED_INHERITANCE
    assert findings[0].actions[0].type is ActionType.CLEAR_BLOCK_INHERITANCE
    assert findings[0].capability.value == "WriteGPOptions"


def test_gplink_right_can_enforce_blocked_ancestor() -> None:
    env = environment(
        domain_links=(Link(DANGEROUS_DN),),
        domain_sd=som_sd(GPLINK_GUID),
        gp_options=1,
        include_safe=False,
    )
    findings = CounterfactualSolver(env).solve()
    assert any(item.actions[0].type is ActionType.SET_ENFORCED for item in findings)


def test_unlinked_gpo_can_be_added_locally() -> None:
    env = environment(ou_sd=som_sd(GPLINK_GUID), include_safe=False)
    findings = CounterfactualSolver(env).solve()
    assert len(findings) == 1
    assert findings[0].reason is DormancyReason.UNLINKED
    assert findings[0].actions[0].type is ActionType.ADD_LINK


def test_security_filter_can_be_changed_with_write_dacl() -> None:
    danger = dangerous_gpo(
        security_descriptor=gpo_sd(target_allowed=False, write_dac=True)
    )
    env = environment(ou_links=(Link(DANGEROUS_DN),), danger=danger, include_safe=False)
    findings = CounterfactualSolver(env).solve()
    assert len(findings) == 1
    assert findings[0].reason is DormancyReason.SECURITY_FILTERED
    assert findings[0].actions[0].type is ActionType.GRANT_READ_APPLY
    assert findings[0].requires_gpo_edit is True


def test_computer_section_can_be_enabled_via_flags_write() -> None:
    danger = dangerous_gpo(flags=2, security_descriptor=gpo_sd(write_flags=True))
    env = environment(ou_links=(Link(DANGEROUS_DN),), danger=danger, include_safe=False)
    findings = CounterfactualSolver(env).solve()
    assert len(findings) == 1
    assert findings[0].reason is DormancyReason.SECTION_DISABLED
    assert findings[0].actions[0].type is ActionType.ENABLE_COMPUTER_SECTION


def test_two_action_path_is_bounded() -> None:
    danger = dangerous_gpo(
        security_descriptor=gpo_sd(target_allowed=False, write_dac=True)
    )
    env = environment(
        ou_links=(Link(DANGEROUS_DN, 1),),
        ou_sd=som_sd(GPLINK_GUID),
        danger=danger,
        include_safe=False,
    )
    assert CounterfactualSolver(env, max_actions=1).solve() == []
    findings = CounterfactualSolver(env, max_actions=2).solve()
    assert len(findings) == 1
    assert {action.type for action in findings[0].actions} == {
        ActionType.ENABLE_LINK,
        ActionType.GRANT_READ_APPLY,
    }


def test_unknown_wmi_and_unreadable_gpt_fail_closed() -> None:
    wmi = dangerous_gpo(wmi_filter="CN={FILTER},CN=SOM,CN=WMIPolicy", wmi_result=None)
    env = environment(
        ou_links=(Link(DANGEROUS_DN, 0, 2), Link(SAFE_DN, 0, 1)),
        ou_sd=som_sd(GPLINK_GUID),
        danger=wmi,
    )
    assert CounterfactualSolver(env).solve() == []

    env.gpos[DANGEROUS_DN.casefold()] = dangerous_gpo(gpt_readable=False)
    assert CounterfactualSolver(env).solve() == []


def test_version_divergence_reduces_confidence() -> None:
    danger = dangerous_gpo(version_number=4, gpt_version=3)
    env = environment(
        ou_links=(Link(DANGEROUS_DN, 0, 2), Link(SAFE_DN, 0, 1)),
        ou_sd=som_sd(GPLINK_GUID),
        danger=danger,
    )
    assert {finding.confidence for finding in CounterfactualSolver(env).solve()} == {
        "MEDIUM"
    }
