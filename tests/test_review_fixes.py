"""Regression tests for the ACL, catalog, solver, collector and reporting fixes
raised in the external review."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from gpowake.acl import (
    ADS_RIGHT_DS_WRITE_PROP,
    GPLINK_GUID,
    OWNER_RIGHTS_SID,
    WRITE_DAC,
    WRITE_OWNER,
    UnsafeDaclRewriteError,
    access_check,
    can_write_dacl,
    capabilities_on_som,
    evaluate_read_gpo,
    evaluate_write_dacl,
    grant_read_apply,
    grant_write_gplink,
    rewrite_read_apply,
    rewrite_read_apply_explicit_blockers,
)
from gpowake.catalog import assess_setting
from gpowake.collectors.ldap import (
    LDAPCollector,
    _token_complete,
    _token_sids,
)
from gpowake.models import (
    Ace,
    AceType,
    AccessDecision,
    ActionType,
    Capability,
    DaclRewriteMode,
    Link,
    Principal,
    ScopeOfManagement,
    SecurityDescriptor,
    Severity,
    Setting,
    SettingKind,
    SomKind,
)
from gpowake.report import render_netexec
from gpowake.solver import CounterfactualSolver, WorkBudgetExceeded

from conftest import (
    ACTOR,
    AUTHENTICATED_USERS,
    DANGEROUS_DN,
    DOMAIN_DN,
    OU_DN,
    SAFE_DN,
    TARGET,
    dangerous_gpo,
    environment,
    gpo_sd,
    som_sd,
)


# --------------------------------------------------------------------------
# 1. Inherit-only ACEs must not apply to the object that carries them.
# --------------------------------------------------------------------------
def test_inherit_only_ace_is_not_effective_on_the_object() -> None:
    descriptor = SecurityDescriptor(
        (
            Ace(
                ACTOR,
                AceType.ALLOW,
                ADS_RIGHT_DS_WRITE_PROP,
                GPLINK_GUID,
                inherit_only=True,
            ),
        )
    )
    assert (
        access_check(descriptor, (ACTOR,), ADS_RIGHT_DS_WRITE_PROP, GPLINK_GUID)
        is AccessDecision.DENY
    )
    som = ScopeOfManagement(DOMAIN_DN, SomKind.DOMAIN, security_descriptor=descriptor)
    assert capabilities_on_som(Principal(ACTOR, "actor", ()), som) == frozenset()


# --------------------------------------------------------------------------
# 2. SELF (S-1-5-10) is not a universal token membership.
# --------------------------------------------------------------------------
def test_self_is_not_added_to_the_token() -> None:
    entry = {
        "raw_attributes": {
            "objectSid": ["S-1-5-21-1-2-3-1100"],
            "tokenGroups": ["S-1-5-21-1-2-3-513"],
        },
        "attributes": {},
    }
    sids = _token_sids(entry)
    assert "S-1-5-10" not in sids
    assert "S-1-1-0" in sids and "S-1-5-11" in sids


def test_self_ace_does_not_grant_arbitrary_actor() -> None:
    descriptor = SecurityDescriptor(
        (Ace("S-1-5-10", AceType.ALLOW, ADS_RIGHT_DS_WRITE_PROP, GPLINK_GUID),)
    )
    som = ScopeOfManagement(OU_DN, SomKind.OU, security_descriptor=descriptor)
    principal = Principal(ACTOR, "actor", (AUTHENTICATED_USERS,))
    assert Capability.WRITE_GPLINK not in capabilities_on_som(principal, som)


# --------------------------------------------------------------------------
# 3. Owners hold implicit WRITE_DAC unless an OWNER RIGHTS ACE constrains them.
# --------------------------------------------------------------------------
def test_owner_holds_implicit_write_dac() -> None:
    descriptor = SecurityDescriptor(
        (), owner_sid=ACTOR, owner_implicit_rights_verified=True
    )
    assert can_write_dacl(descriptor, (ACTOR,)) is True
    assert can_write_dacl(descriptor, ("S-1-5-21-9-9-9-9",)) is False


def test_owner_rights_ace_constrains_the_owner() -> None:
    descriptor = SecurityDescriptor(
        (Ace(OWNER_RIGHTS_SID, AceType.ALLOW, 0),), owner_sid=ACTOR
    )
    assert evaluate_write_dacl(descriptor, (ACTOR,)).decision is AccessDecision.DENY


def test_owner_does_not_hold_implicit_write_owner() -> None:
    descriptor = SecurityDescriptor((), owner_sid=ACTOR)
    assert access_check(descriptor, (ACTOR,), WRITE_OWNER) is AccessDecision.DENY


def test_unsupported_owner_rights_ace_is_unknown() -> None:
    descriptor = SecurityDescriptor(
        (Ace(OWNER_RIGHTS_SID, AceType.UNSUPPORTED, WRITE_DAC),), owner_sid=ACTOR
    )
    assert (
        evaluate_write_dacl(descriptor, (ACTOR,)).decision
        is AccessDecision.UNKNOWN
    )


def test_block_owner_implicit_rights_suppresses_write_dac() -> None:
    descriptor = SecurityDescriptor(
        (), owner_sid=ACTOR, owner_implicit_rights_blocked=True
    )
    assert evaluate_write_dacl(descriptor, (ACTOR,)).decision is AccessDecision.DENY


def test_unverified_owner_implicit_rights_are_unknown() -> None:
    descriptor = SecurityDescriptor((), owner_sid=ACTOR)
    assert (
        evaluate_write_dacl(descriptor, (ACTOR,)).decision
        is AccessDecision.UNKNOWN
    )
    assert can_write_dacl(descriptor, (ACTOR,)) is False


def test_access_decision_cannot_be_used_as_a_boolean() -> None:
    with pytest.raises(TypeError, match="no truth value"):
        bool(AccessDecision.DENY)


def test_solver_candidate_budget_fails_instead_of_returning_partial_results() -> None:
    env = environment(ou_sd=som_sd(GPLINK_GUID), include_safe=False)
    env.principals.append(
        Principal("S-1-5-21-1-2-3-1101", "second actor", ())
    )
    solver = CounterfactualSolver(env, max_candidate_evaluations=1)
    estimate = solver.estimate_work()
    assert estimate.candidate_evaluations_upper_bound == 2
    with pytest.raises(WorkBudgetExceeded, match="candidate-evaluation budget"):
        solver.solve()


def test_solver_transition_budget_bounds_one_candidate_action_explosion() -> None:
    env = environment(ou_sd=som_sd(GPLINK_GUID), include_safe=False)
    with pytest.raises(WorkBudgetExceeded, match="transition-evaluation budget"):
        CounterfactualSolver(env, max_transition_evaluations=1).solve()


def test_solver_finding_budget_fails_instead_of_silently_truncating() -> None:
    original = dangerous_gpo()
    second = Setting(
        SettingKind.REGISTRY,
        "HKLM\\Software\\Policies\\Example\\Dangerous",
        1,
        dangerous=True,
        severity=Severity.HIGH,
    )
    env = environment(
        danger=replace(original, settings=(*original.settings, second)),
        ou_sd=som_sd(GPLINK_GUID),
        include_safe=False,
    )
    with pytest.raises(WorkBudgetExceeded, match="finding budget"):
        CounterfactualSolver(env, max_findings=1).solve()


def test_solver_coverage_gap_budget_prevents_uncertainty_memory_bypass() -> None:
    env = environment(
        danger=dangerous_gpo(
            settings=(),
            settings_complete=False,
            settings_uncertainty_reasons=("GptTmpl.inf unavailable",),
        )
    )
    env.gpos = {
        key: replace(
            gpo,
            settings=(),
            settings_complete=False,
            settings_uncertainty_reasons=("policy input unavailable",),
        )
        for key, gpo in env.gpos.items()
    }
    solver = CounterfactualSolver(env, max_coverage_gaps=1)
    assert solver.estimate_work().coverage_gap_checks_upper_bound == 2
    with pytest.raises(WorkBudgetExceeded, match="coverage-gap budget"):
        solver.solve()


# --------------------------------------------------------------------------
# 4. Unsupported ACE types fail closed instead of being silently dropped.
# --------------------------------------------------------------------------
def test_unsupported_ace_for_the_actor_fails_closed() -> None:
    descriptor = SecurityDescriptor(
        (
            Ace(ACTOR, AceType.UNSUPPORTED, 0),
            Ace(ACTOR, AceType.ALLOW, ADS_RIGHT_DS_WRITE_PROP, GPLINK_GUID),
        )
    )
    assert (
        access_check(descriptor, (ACTOR,), ADS_RIGHT_DS_WRITE_PROP, GPLINK_GUID)
        is AccessDecision.UNKNOWN
    )


def test_unsupported_ace_for_other_trustee_is_ignored() -> None:
    descriptor = SecurityDescriptor(
        (
            Ace("S-1-5-32-544", AceType.UNSUPPORTED, 0),
            Ace(ACTOR, AceType.ALLOW, ADS_RIGHT_DS_WRITE_PROP, GPLINK_GUID),
        )
    )
    assert (
        access_check(descriptor, (ACTOR,), ADS_RIGHT_DS_WRITE_PROP, GPLINK_GUID)
        is AccessDecision.ALLOW
    )


def test_unsupported_ace_with_undecodable_trustee_is_unknown() -> None:
    descriptor = SecurityDescriptor(
        (
            Ace("", AceType.UNSUPPORTED, 0),
            Ace(ACTOR, AceType.ALLOW, ADS_RIGHT_DS_WRITE_PROP, GPLINK_GUID),
        )
    )
    assert (
        access_check(descriptor, (ACTOR,), ADS_RIGHT_DS_WRITE_PROP, GPLINK_GUID)
        is AccessDecision.UNKNOWN
    )


# --------------------------------------------------------------------------
# 5. Per-privilege expected-assignment catalog.
# --------------------------------------------------------------------------
def _privilege(name: str, *sids: str) -> Setting:
    return assess_setting(Setting(SettingKind.PRIVILEGE_RIGHT, name, tuple(sids)))


def test_sedebug_on_backup_operators_is_flagged() -> None:
    assert _privilege("SeDebugPrivilege", "S-1-5-32-551").dangerous is True


def test_setcb_on_network_service_is_flagged() -> None:
    assert _privilege("SeTcbPrivilege", "S-1-5-20").dangerous is True


def test_seimpersonate_on_network_service_is_expected() -> None:
    assert _privilege("SeImpersonatePrivilege", "S-1-5-20").dangerous is False


def test_sebackup_on_backup_operators_is_expected() -> None:
    assert _privilege("SeBackupPrivilege", "S-1-5-32-551").dangerous is False


def test_admin_equivalent_assignment_is_expected() -> None:
    setting = Setting(
        SettingKind.PRIVILEGE_RIGHT,
        "SeDebugPrivilege",
        ("S-1-5-21-1-2-3-512",),
    )
    assessed = assess_setting(setting, {"S-1-5-21-1-2-3-512"})
    assert assessed.dangerous is False


def test_external_admin_rid_is_not_implicitly_trusted() -> None:
    setting = Setting(
        SettingKind.PRIVILEGE_RIGHT,
        "SeDebugPrivilege",
        ("S-1-5-21-9-9-9-512",),
    )
    assessed = assess_setting(setting, {"S-1-5-21-1-2-3-512"})
    assert assessed.dangerous is True
    assert assessed.unexpected_trustees == ("S-1-5-21-9-9-9-512",)


def test_restricted_administrators_delta_excludes_existing_member() -> None:
    existing = "S-1-5-21-1-2-3-1100"
    added = "S-1-5-21-1-2-3-1101"
    candidate = assess_setting(
        Setting(
            SettingKind.RESTRICTED_GROUP,
            "S-1-5-32-544/Members",
            (existing, added),
        )
    )
    current = Setting(
        SettingKind.RESTRICTED_GROUP,
        "S-1-5-32-544/Members",
        (existing,),
    )
    assert CounterfactualSolver._newly_privileged(
        candidate, SimpleNamespace(setting=current)
    ) == (added,)


@pytest.mark.parametrize(
    ("name", "candidate_value", "current_value", "unexpected"),
    (
        (
            "S-1-5-32-544/Members",
            ("S-1-5-21-1-2-3-1100",),
            ("S-1-5-21-1-2-3-1100", "S-1-5-21-1-2-3-1101"),
            "S-1-5-21-1-2-3-1100",
        ),
        (
            "S-1-5-21-1-2-3-1100/MemberOf",
            ("S-1-5-32-544",),
            ("S-1-5-32-544", "S-1-5-32-545"),
            "S-1-5-21-1-2-3-1100",
        ),
    ),
)
def test_restricted_group_removal_only_overlap_emits_no_finding(
    name, candidate_value, current_value, unexpected
) -> None:
    candidate = Setting(
        SettingKind.RESTRICTED_GROUP,
        name,
        candidate_value,
        dangerous=True,
        severity=Severity.CRITICAL,
        unexpected_trustees=(unexpected,),
    )
    current = Setting(SettingKind.RESTRICTED_GROUP, name, current_value)
    env = environment(
        ou_links=(Link(DANGEROUS_DN, 0, 2), Link(SAFE_DN, 0, 1)),
        ou_sd=som_sd(GPLINK_GUID),
        danger=dangerous_gpo(settings=(candidate,)),
    )
    safe = env.gpo(SAFE_DN)
    assert safe is not None
    env.gpos[safe.dn.casefold()] = replace(safe, settings=(current,))

    findings = CounterfactualSolver(env).solve()
    assert not [item for item in findings if item.setting_name == name]


# --------------------------------------------------------------------------
# 6. Add-link transitions consider every applicable scope, not just the OU.
# --------------------------------------------------------------------------
def test_add_link_considers_domain_scope() -> None:
    env = environment(domain_sd=som_sd(GPLINK_GUID), include_safe=False)
    findings = CounterfactualSolver(env).solve()
    assert len(findings) == 1
    finding = findings[0]
    assert finding.reason.value == "UNLINKED"
    assert finding.actions[0].type is ActionType.ADD_LINK
    assert finding.actions[0].som_dn == DOMAIN_DN


# --------------------------------------------------------------------------
# 7. WRITE_DAC on a SOM yields a two-step grant-then-link path.
# --------------------------------------------------------------------------
def test_write_dac_on_som_enables_two_step_link() -> None:
    ou_sd = SecurityDescriptor((Ace(ACTOR, AceType.ALLOW, WRITE_DAC),))
    env = environment(ou_sd=ou_sd, include_safe=False)
    assert CounterfactualSolver(env, max_actions=1).solve() == []
    findings = CounterfactualSolver(env, max_actions=2).solve()
    assert len(findings) == 1
    assert {action.type for action in findings[0].actions} == {
        ActionType.GRANT_GPLINK,
        ActionType.ADD_LINK,
    }


def test_capability_cache_key_includes_complete_token() -> None:
    group = "S-1-5-21-1-2-3-2600"
    som = ScopeOfManagement(
        OU_DN,
        SomKind.OU,
        security_descriptor=SecurityDescriptor(
            (Ace(group, AceType.ALLOW, ADS_RIGHT_DS_WRITE_PROP, GPLINK_GUID),)
        ),
    )
    solver = CounterfactualSolver(environment(include_safe=False))
    without_group = Principal(ACTOR, "actor", ())
    with_group = Principal(ACTOR, "actor", (group,))
    assert Capability.WRITE_GPLINK not in solver._caps_som(without_group, som)
    assert Capability.WRITE_GPLINK in solver._caps_som(with_group, som)
    assert solver._caps_som(replace(with_group, token_incomplete=True), som) == (
        frozenset()
    )


# --------------------------------------------------------------------------
# 8. Missing tokenGroups fails closed to LOW confidence.
# --------------------------------------------------------------------------
def test_token_complete_detects_missing_tokengroups() -> None:
    assert _token_complete({"raw_attributes": {"tokenGroups": ["S-1-5-32-544"]}})
    assert not _token_complete({"raw_attributes": {"objectSid": ["S-1-5-21-1"]}})


def test_incomplete_actor_token_produces_no_optimistic_path(base_environment) -> None:
    env = base_environment
    env.principals = [replace(env.principals[0], token_incomplete=True)]
    findings = CounterfactualSolver(env).solve()
    assert findings == []


# --------------------------------------------------------------------------
# 9. Alternative activation paths collapse into one finding.
# --------------------------------------------------------------------------
def test_reorder_and_enforce_are_one_finding(base_environment) -> None:
    findings = CounterfactualSolver(base_environment).solve()
    assert len(findings) == 1
    path_types = {tuple(a.type for a in path) for path in findings[0].paths}
    assert (ActionType.REORDER_LINK,) in path_types
    assert (ActionType.SET_ENFORCED,) in path_types


def test_equivalent_targets_are_emitted_as_one_finding(base_environment) -> None:
    template = base_environment.targets[0]
    base_environment.targets = [
        replace(
            template,
            dn=f"CN=SRV{index},{OU_DN}",
            name=f"SRV{index}",
            sid=f"S-1-5-21-1-2-3-{2100 + index}",
        )
        for index in range(100)
    ]
    findings = CounterfactualSolver(base_environment).solve()
    assert len(findings) == 1
    assert len(findings[0].targets) == 100


def test_netexec_output_shape(base_environment) -> None:
    findings = CounterfactualSolver(base_environment).solve()
    rendered = render_netexec(findings)
    assert rendered.startswith("GPOWAKE")
    assert "[?]" in rendered
    assert "alt: SetEnforced" in rendered


def test_dacl_rewrite_refuses_explicit_deny() -> None:
    descriptor = SecurityDescriptor(
        (
            Ace(AUTHENTICATED_USERS, AceType.DENY, ADS_RIGHT_DS_WRITE_PROP, GPLINK_GUID),
        )
    )
    with pytest.raises(UnsafeDaclRewriteError, match="refusing to weaken"):
        grant_write_gplink(descriptor, ACTOR, (ACTOR, AUTHENTICATED_USERS))


def test_read_apply_rewrite_refuses_generic_explicit_deny() -> None:
    descriptor = SecurityDescriptor(
        (Ace(AUTHENTICATED_USERS, AceType.DENY, 0x10000000),)
    )
    with pytest.raises(UnsafeDaclRewriteError, match="refusing to weaken"):
        grant_read_apply(
            descriptor,
            "S-1-5-21-1-2-3-2100",
            ("S-1-5-21-1-2-3-2100", AUTHENTICATED_USERS),
        )


def test_explicit_blocker_rewrite_is_opt_in_and_reports_exact_collateral() -> None:
    descriptor = SecurityDescriptor(
        (
            Ace(TARGET, AceType.DENY, 0x10000000),
            Ace(ACTOR, AceType.ALLOW, WRITE_DAC),
        )
    )
    rewritten, removed, added = rewrite_read_apply_explicit_blockers(
        descriptor, TARGET, (TARGET, AUTHENTICATED_USERS)
    )
    assert removed == (descriptor.aces[0],)
    assert added
    assert descriptor.aces[1] in rewritten.aces

    danger = dangerous_gpo(security_descriptor=descriptor)
    env = environment(
        ou_links=(Link(DANGEROUS_DN),), danger=danger, include_safe=False
    )
    assert CounterfactualSolver(env).solve() == []
    findings = CounterfactualSolver(env, explicit_blocker_rewrite=True).solve()
    assert len(findings) == 1
    action = findings[0].actions[0]
    assert action.type is ActionType.REWRITE_READ_APPLY_DACL
    assert action.dacl_rewrite_mode is DaclRewriteMode.EXPLICIT_BLOCKER_REWRITE
    assert action.dacl_removed == (descriptor.aces[0],)
    assert action.collateral_trustees == (TARGET,)
    assert "unobserved trustee members" in action.collateral_effects[0]


def test_undecodable_explicit_ace_dispatches_to_explicit_blocker_solver_path() -> None:
    descriptor = SecurityDescriptor(
        (
            Ace(ACTOR, AceType.ALLOW, WRITE_DAC),
            Ace("", AceType.UNSUPPORTED, 0),
        ),
        has_unsupported_ace=True,
    )
    with pytest.raises(UnsafeDaclRewriteError, match="undecodable trustee"):
        rewrite_read_apply(descriptor, TARGET, (TARGET, AUTHENTICATED_USERS))

    danger = dangerous_gpo(security_descriptor=descriptor)
    env = environment(
        ou_links=(Link(DANGEROUS_DN),), danger=danger, include_safe=False
    )
    assert CounterfactualSolver(env).solve() == []
    findings = CounterfactualSolver(
        env, explicit_blocker_rewrite=True
    ).solve()
    assert len(findings) == 1
    action = findings[0].actions[0]
    assert action.type is ActionType.REWRITE_READ_APPLY_DACL
    assert action.dacl_removed == (descriptor.aces[1],)
    assert action.collateral_trustees == ("UNKNOWN_TRUSTEE",)


def test_additive_dacl_rewrite_preserves_every_existing_ace_order() -> None:
    existing = (
        Ace("S-1-5-32-544", AceType.ALLOW, WRITE_DAC),
        Ace("S-1-5-32-545", AceType.DENY, WRITE_OWNER, inherited=True),
        Ace("S-1-5-32-546", AceType.ALLOW, WRITE_OWNER),
    )
    rewritten, removed, added = rewrite_read_apply(
        SecurityDescriptor(existing), "S-1-5-21-1-2-3-2100"
    )
    assert removed == ()
    assert added
    assert tuple(ace for ace in rewritten.aces if ace not in added) == existing


def test_unresolved_membership_only_affects_dacl_that_names_trustee(
    base_environment,
) -> None:
    unresolved = "S-1-5-21-9-9-9-2500"
    danger = base_environment.gpo(DANGEROUS_DN)
    assert danger is not None
    base_environment.gpos[DANGEROUS_DN.casefold()] = replace(
        danger,
        security_descriptor=replace(
            danger.security_descriptor,
            aces=(
                Ace(unresolved, AceType.DENY, 0x80000000),
                *danger.security_descriptor.aces,
            ),
        ),
    )
    target = replace(
        base_environment.targets[0], unresolved_token_sids=(unresolved,)
    )
    base_environment.targets = [target]
    evaluation = CounterfactualSolver(base_environment)._evaluate(
        base_environment, target
    )
    by_gpo = {item.link.gpo_dn.casefold(): item for item in evaluation.links}
    assert by_gpo[DANGEROUS_DN.casefold()].uncertain is True
    assert by_gpo[SAFE_DN.casefold()].status.value == "APPLIES"

    safe = base_environment.gpo(SAFE_DN)
    assert safe is not None
    assert (
        evaluate_read_gpo(
            safe.security_descriptor,
            target.all_sids,
            unresolved_token_sids=target.unresolved_sids,
        ).decision
        is AccessDecision.ALLOW
    )


def test_target_specific_acl_findings_are_split_and_replayable() -> None:
    danger = dangerous_gpo(
        security_descriptor=gpo_sd(target_allowed=False, write_dac=True)
    )
    env = environment(
        ou_links=(Link(DANGEROUS_DN),),
        danger=danger,
        include_safe=False,
    )
    template = env.targets[0]
    env.targets = [
        replace(
            template,
            dn=f"CN=SRV{index},{OU_DN}",
            name=f"SRV{index}",
            sid=f"S-1-5-21-1-2-3-{2100 + index}",
        )
        for index in range(2)
    ]
    solver = CounterfactualSolver(env)
    findings = solver.solve()
    assert len(findings) == 2
    targets_by_dn = {target.dn: target for target in env.targets}
    for finding in findings:
        assert len(finding.target_dns) == 1
        action = finding.actions[0]
        target = targets_by_dn[finding.target_dns[0]]
        assert action.target_sid == target.sid
        assert action.target_sids == (target.sid,)
        assert solver._path_wins(finding.actions, target, danger, danger.settings[0])


def test_solver_rejects_ambiguous_target_identity(base_environment) -> None:
    duplicate = replace(
        base_environment.targets[0],
        dn="CN=OTHER," + OU_DN,
        name="OTHER",
    )
    base_environment.targets.append(duplicate)
    with pytest.raises(ValueError, match="target SIDs must be unique"):
        CounterfactualSolver(base_environment)


# --------------------------------------------------------------------------
# 10. Target selection is applied on cheap attributes (name / DN / SID).
# --------------------------------------------------------------------------
def test_target_selection_matches_name_dn_and_sid() -> None:
    entry = {
        "dn": "CN=DC01,OU=Domain Controllers,DC=corp,DC=local",
        "attributes": {"dNSHostName": "dc01.corp.local", "name": "DC01"},
        "raw_attributes": {"objectSid": ["S-1-5-21-1-2-3-1001"]},
    }
    assert LDAPCollector._target_selected(entry, ())
    assert LDAPCollector._target_selected(entry, ("dc01.corp.local",))
    assert LDAPCollector._target_selected(entry, ("DC01",))
    assert LDAPCollector._target_selected(entry, ("S-1-5-21-1-2-3-1001",))
    assert not LDAPCollector._target_selected(entry, ("someone-else",))
