from __future__ import annotations

from dataclasses import replace

from gpowake.acl import GPLINK_GUID, GPOPTIONS_GUID
from gpowake.models import (
    AccessDecision,
    ActionType,
    DormancyReason,
    Link,
    SettingKind,
)
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


def test_wmi_results_are_target_specific() -> None:
    wmi_filter = "CN={FILTER},CN=SOM,CN=WMIPolicy"
    danger = dangerous_gpo(wmi_filter=wmi_filter)
    env = environment(
        ou_links=(Link(DANGEROUS_DN, 0, 2), Link(SAFE_DN, 0, 1)),
        ou_sd=som_sd(GPLINK_GUID),
        danger=danger,
    )
    template = env.targets[0]
    env.targets = [
        replace(
            template,
            name="WMI-TRUE",
            dn="CN=WMI-TRUE," + template.som_dn,
            sid="S-1-5-21-1-2-3-2201",
            wmi_results=((wmi_filter, True),),
        ),
        replace(
            template,
            name="WMI-FALSE",
            dn="CN=WMI-FALSE," + template.som_dn,
            sid="S-1-5-21-1-2-3-2202",
            wmi_results=((wmi_filter, False),),
        ),
    ]
    findings = CounterfactualSolver(env).solve()
    assert findings
    assert {name for finding in findings for name in finding.targets} == {"WMI-TRUE"}


def test_legacy_global_true_wmi_result_is_not_treated_as_all_targets_true() -> None:
    danger = dangerous_gpo(
        wmi_filter="CN={FILTER},CN=SOM,CN=WMIPolicy", wmi_result=True
    )
    env = environment(
        ou_links=(Link(DANGEROUS_DN, 0, 2), Link(SAFE_DN, 0, 1)),
        ou_sd=som_sd(GPLINK_GUID),
        danger=danger,
    )
    solver = CounterfactualSolver(env)
    assert solver.solve() == []
    assert any(gap.gate == "WMI_FILTER" for gap in solver.coverage_gaps)


def test_version_divergence_is_structured_uncertainty() -> None:
    danger = dangerous_gpo(version_number=4, gpt_version=3)
    env = environment(
        ou_links=(Link(DANGEROUS_DN, 0, 2), Link(SAFE_DN, 0, 1)),
        ou_sd=som_sd(GPLINK_GUID),
        danger=danger,
    )
    findings = CounterfactualSolver(env).solve()
    assert findings
    assert all(
        "AD and GPT versions diverge" in finding.uncertainty_reasons
        for finding in findings
    )


def test_live_collector_gpt_read_is_not_target_authorization() -> None:
    env = environment(
        ou_links=(Link(DANGEROUS_DN, 0, 2), Link(SAFE_DN, 0, 1)),
        ou_sd=som_sd(GPLINK_GUID),
    )
    env.collected_at = "2026-08-25T00:00:00+00:00"
    for key, gpo in list(env.gpos.items()):
        env.gpos[key] = replace(
            gpo, collector_gpt_readable=True, functionality_version=2
        )
    solver = CounterfactualSolver(env)
    assert solver.solve() == []
    assert any(gap.gate == "TARGET_GPT_READ" for gap in solver.coverage_gaps)

    env.targets[0] = replace(
        env.targets[0],
        gpt_read_decisions=(
            (DANGEROUS_DN, AccessDecision.ALLOW),
            (SAFE_DN, AccessDecision.ALLOW),
        ),
    )
    assert CounterfactualSolver(env).solve()


def test_incomplete_settings_and_site_resolution_block_findings() -> None:
    env = environment(
        ou_links=(Link(DANGEROUS_DN, 0, 2), Link(SAFE_DN, 0, 1)),
        ou_sd=som_sd(GPLINK_GUID),
    )
    safe = env.gpo(SAFE_DN)
    assert safe is not None
    env.gpos[SAFE_DN.casefold()] = replace(
        safe,
        settings_complete=False,
        settings_uncertainty_reasons=("Registry.pol read failed",),
    )
    solver = CounterfactualSolver(env)
    assert solver.solve() == []
    assert any("Registry.pol read failed" in gap.reason for gap in solver.coverage_gaps)

    env.gpos[SAFE_DN.casefold()] = safe
    env.targets[0] = replace(
        env.targets[0], site_resolution_error="target site could not be resolved"
    )
    site_solver = CounterfactualSolver(env)
    assert site_solver.solve() == []
    assert any("site could not be resolved" in gap.reason for gap in site_solver.coverage_gaps)


def test_unrelated_incomplete_setting_family_does_not_poison_candidate() -> None:
    env = environment(
        ou_links=(Link(DANGEROUS_DN, 0, 2), Link(SAFE_DN, 0, 1)),
        ou_sd=som_sd(GPLINK_GUID),
    )
    safe = env.gpo(SAFE_DN)
    assert safe is not None
    env.gpos[SAFE_DN.casefold()] = replace(
        safe,
        settings_complete=False,
        settings_uncertainty_reasons=("Registry.pol read failed",),
        incomplete_setting_kinds=(SettingKind.REGISTRY,),
    )
    assert CounterfactualSolver(env).solve()

    env.gpos[SAFE_DN.casefold()] = replace(
        safe,
        settings_complete=False,
        settings_uncertainty_reasons=("GptTmpl.inf read failed",),
        incomplete_setting_kinds=(SettingKind.PRIVILEGE_RIGHT,),
    )
    solver = CounterfactualSolver(env)
    assert solver.solve() == []
    assert any("GptTmpl.inf" in gap.reason for gap in solver.coverage_gaps)


def test_missing_linked_gpo_is_a_coverage_gap() -> None:
    missing = "CN={CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC},CN=Policies,CN=System,DC=corp,DC=local"
    env = environment(
        ou_links=(Link(DANGEROUS_DN, 0, 2), Link(missing, 0, 1)),
        ou_sd=som_sd(GPLINK_GUID),
        include_safe=False,
    )
    solver = CounterfactualSolver(env)
    assert solver.solve() == []
    assert any(gap.gate == "GPO_COLLECTION" for gap in solver.coverage_gaps)


def test_incomplete_gpt_is_reported_even_when_no_dangerous_setting_was_parsed() -> None:
    danger = dangerous_gpo(
        settings=(),
        settings_complete=False,
        settings_uncertainty_reasons=("GptTmpl.inf parse failed",),
    )
    env = environment(danger=danger, include_safe=False)
    solver = CounterfactualSolver(env)
    assert solver.solve() == []
    assert len(solver.coverage_gaps) == 1
    assert solver.coverage_gaps[0].gate == "GPT_SETTINGS"
