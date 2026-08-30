from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, replace
from typing import Iterable

from .acl import (
    ADS_RIGHT_DS_WRITE_PROP,
    FLAGS_GUID,
    GPLINK_GUID,
    GPOPTIONS_GUID,
    WRITE_DAC,
    UnsafeDaclRewriteError,
    capabilities_on_gpo,
    capabilities_on_som,
    evaluate_access,
    evaluate_apply_gpo,
    evaluate_read_gpo,
    grant_read_apply,
    grant_write_gplink,
    rewrite_read_apply,
    rewrite_read_apply_explicit_blockers,
    rewrite_write_gplink,
    rewrite_write_gplink_explicit_blockers,
)
from .catalog import assess_setting
from .gplink import reorder_link
from .models import (
    Ace,
    Action,
    ActionType,
    AccessDecision,
    Capability,
    Confidence,
    CoverageGap,
    DormancyReason,
    DaclRewriteMode,
    Environment,
    Finding,
    GPO,
    GptAccessProvenance,
    Link,
    Principal,
    ScopeOfManagement,
    SecurityDescriptor,
    Severity,
    Setting,
    SettingKind,
    Target,
    normalize_dn,
    normalize_sid,
)
from .precedence import Evaluation, EffectiveSetting, PolicyEngine, PolicyUncertainty
from .redaction import redact_value


_SEVERITY_SCORE = {
    Severity.LOW: 3.0,
    Severity.MEDIUM: 5.5,
    Severity.HIGH: 8.0,
    Severity.CRITICAL: 9.3,
}

_GPO_EDIT_ACTIONS = {
    ActionType.GRANT_READ_APPLY,
    ActionType.REWRITE_READ_APPLY_DACL,
    ActionType.ENABLE_COMPUTER_SECTION,
}

_MAX_TRACE_VALUE_CHARS = 192
_MAX_TRACE_LINE_CHARS = 512


@dataclass(frozen=True)
class WorkEstimate:
    principals: int
    targets: int
    target_equivalence_groups: int
    dangerous_settings: int
    candidate_evaluations_upper_bound: int
    coverage_gap_checks_upper_bound: int


class WorkBudgetExceeded(RuntimeError):
    """Raised instead of returning a silently incomplete security report."""


def _clone(environment: Environment) -> Environment:
    """Cheap copy for transition search.

    Every mutable container (``soms``/``gpos``) is shallow-copied; their values
    are frozen dataclasses that ``apply_action`` only ever replaces immutably, so
    a full ``deepcopy`` of principals, targets, settings and descriptors is pure
    waste. Principals/targets/warnings are never mutated during search and are
    shared by reference.
    """
    return Environment(
        soms=dict(environment.soms),
        gpos=dict(environment.gpos),
        principals=environment.principals,
        targets=environment.targets,
        source_dc=environment.source_dc,
        warnings=environment.warnings,
        domain_sid=environment.domain_sid,
        forest_root_sid=environment.forest_root_sid,
        ldap_endpoint=environment.ldap_endpoint,
        smb_endpoint=environment.smb_endpoint,
        tls_verified=environment.tls_verified,
        collected_at=environment.collected_at,
    )


class CounterfactualSolver:
    def __init__(
        self,
        environment: Environment,
        max_actions: int = 1,
        *,
        explicit_blocker_rewrite: bool = False,
        max_candidate_evaluations: int = 250_000,
        max_transition_evaluations: int = 2_000_000,
        max_findings: int = 100_000,
        max_coverage_gaps: int = 100_000,
    ):
        if max_actions < 1 or max_actions > 2:
            raise ValueError("max_actions must be 1 or 2")
        if min(
            max_candidate_evaluations,
            max_transition_evaluations,
            max_findings,
            max_coverage_gaps,
        ) < 1:
            raise ValueError("solver work limits must be positive")
        target_dns = [normalize_dn(item.dn) for item in environment.targets]
        target_sids = [normalize_sid(item.sid) for item in environment.targets]
        principal_sids = [normalize_sid(item.sid) for item in environment.principals]
        if len(target_dns) != len(set(target_dns)):
            raise ValueError("target DNs must be unique")
        if len(target_sids) != len(set(target_sids)):
            raise ValueError("target SIDs must be unique")
        if len(principal_sids) != len(set(principal_sids)):
            raise ValueError("principal SIDs must be unique")
        for target in environment.targets:
            wmi_ids = [normalize_dn(item[0]) for item in target.wmi_results]
            raw_gpt_ids = [item[0] for item in target.gpt_read_decisions]
            raw_gpt_ids.extend(item.gpo_id for item in target.gpt_read_observations)
            gpt_ids: list[str] = []
            for identifier in raw_gpt_ids:
                matches = [
                    gpo
                    for gpo in environment.gpos.values()
                    if gpo.matches_identifier(identifier)
                ]
                if len(matches) != 1:
                    raise ValueError(
                        f"target {target.dn} GPT observation refers to an "
                        f"unknown or ambiguous GPO: {identifier}"
                    )
                gpt_ids.append(normalize_dn(matches[0].dn))
            if len(wmi_ids) != len(set(wmi_ids)):
                raise ValueError(f"target {target.dn} has duplicate WMI observations")
            if len(gpt_ids) != len(set(gpt_ids)):
                raise ValueError(f"target {target.dn} has duplicate GPT read decisions")
        self.environment = environment
        self.max_actions = max_actions
        self.explicit_blocker_rewrite = explicit_blocker_rewrite
        self.max_candidate_evaluations = max_candidate_evaluations
        self.max_transition_evaluations = max_transition_evaluations
        self.max_findings = max_findings
        self.max_coverage_gaps = max_coverage_gaps
        self.candidate_evaluations = 0
        self.transition_evaluations = 0
        self._som_caps: dict[
            tuple[frozenset[str], bool, object], frozenset[Capability]
        ] = {}
        self._gpo_caps: dict[
            tuple[frozenset[str], bool, object, tuple[str, ...]], frozenset[Capability]
        ] = {}
        self._base_eval: dict[Target, Evaluation] = {}
        self._state_eval: dict[tuple[object, Target], Evaluation] = {}
        self.coverage_gaps: list[CoverageGap] = []
        self._coverage_gap_keys: set[tuple[str, ...]] = set()

    def estimate_work(self) -> WorkEstimate:
        """Return a cheap, deterministic upper bound before transition search."""

        dangerous = self._dangerous_pairs()
        referenced = self._referenced_sids()
        groups = {
            self._group_key(target, referenced) for target in self.environment.targets
        }
        return WorkEstimate(
            principals=len(self.environment.principals),
            targets=len(self.environment.targets),
            target_equivalence_groups=len(groups),
            dangerous_settings=len(dangerous),
            candidate_evaluations_upper_bound=(
                len(self.environment.principals) * len(groups) * len(dangerous)
            ),
            coverage_gap_checks_upper_bound=max(
                len(self.environment.principals) * len(groups) * len(dangerous),
                len(self.environment.principals)
                * len(self.environment.targets)
                * sum(not gpo.settings_complete for gpo in self.environment.gpos.values()),
            ),
        )

    def _caps_som(
        self, principal: Principal, som: ScopeOfManagement
    ) -> frozenset[Capability]:
        key = (principal.all_sids, principal.token_incomplete, som.security_descriptor)
        cached = self._som_caps.get(key)
        if cached is None:
            cached = capabilities_on_som(principal, som)
            self._som_caps[key] = cached
        return cached

    def _caps_gpo(self, principal: Principal, gpo: GPO) -> frozenset[Capability]:
        key = (
            principal.all_sids,
            principal.token_incomplete,
            gpo.security_descriptor,
            gpo.file_acl_writable_sids,
        )
        cached = self._gpo_caps.get(key)
        if cached is None:
            cached = capabilities_on_gpo(principal, gpo)
            self._gpo_caps[key] = cached
        return cached

    def _evaluate(self, environment: Environment, target: Target) -> Evaluation:
        if environment is self.environment:
            cached = self._base_eval.get(target)
            if cached is None:
                cached = PolicyEngine(environment).evaluate(target)
                self._base_eval[target] = cached
            return cached
        fingerprint = self._state_fingerprint(environment)
        key = (fingerprint, target)
        cached = self._state_eval.get(key)
        if cached is None:
            cached = PolicyEngine(environment).evaluate(target)
            self._state_eval[key] = cached
        return cached

    @staticmethod
    def _state_fingerprint(environment: Environment) -> tuple[object, ...]:
        """Hashable immutable overlay identity for modified policy state."""

        soms = tuple(
            sorted(
                (
                    normalize_dn(som.dn),
                    som.gp_options,
                    som.links,
                    som.security_descriptor,
                )
                for som in environment.soms.values()
            )
        )
        gpos = tuple(
            sorted(
                (
                    normalize_dn(gpo.dn),
                    gpo.flags,
                    gpo.security_descriptor,
                )
                for gpo in environment.gpos.values()
            )
        )
        return soms, gpos

    def _apply_transition(
        self, environment: Environment, action: Action
    ) -> Environment:
        self.transition_evaluations += 1
        if self.transition_evaluations > self.max_transition_evaluations:
            raise WorkBudgetExceeded(
                f"transition-evaluation budget exceeded "
                f"({self.max_transition_evaluations}); narrow the scan or raise "
                "--max-transitions"
            )
        return self.apply_action(environment, action)

    def _candidate_wins(
        self, environment: Environment, target: Target, gpo: GPO, setting: Setting
    ) -> bool:
        evaluation = self._evaluate(environment, target)
        if evaluation.uncertainties_for(setting):
            return False
        if PolicyEngine.is_restricted_member_of(setting):
            return any(
                not contributor.uncertain
                and normalize_dn(contributor.gpo.dn) == normalize_dn(gpo.dn)
                and contributor.setting.value == setting.value
                for contributor in evaluation.additive_contributors.get(
                    setting.key, ()
                )
            )
        winner = evaluation.winners.get(setting.key)
        return (
            winner is not None
            and not winner.uncertain
            and normalize_dn(winner.gpo.dn) == normalize_dn(gpo.dn)
            and winner.setting.value == setting.value
        )

    def _uncertainties_can_be_replayed_after_dacl_rewrite(
        self,
        uncertainties: tuple[PolicyUncertainty, ...],
        candidate: GPO,
    ) -> bool:
        if not self.explicit_blocker_rewrite or not uncertainties:
            return False
        return all(
            item.gate == "SECURITY_FILTER"
            and normalize_dn(item.gpo_dn or "") == normalize_dn(candidate.dn)
            for item in uncertainties
        )

    @staticmethod
    def _collateral_trustees(removed: tuple[Ace, ...]) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(
                normalize_sid(ace.trustee_sid)
                if ace.trustee_sid
                else "UNKNOWN_TRUSTEE"
                for ace in removed
            )
        )

    @staticmethod
    def _removed_ace_effects(removed: tuple[Ace, ...]) -> list[str]:
        return [
            (
                f"removed {ace.ace_type.value} ACE trustee="
                f"{ace.trustee_sid or 'UNKNOWN_TRUSTEE'} "
                f"mask=0x{ace.access_mask:08x} object={ace.object_type or 'all'}; "
                "unobserved trustee members may gain unrelated rights"
            )
            for ace in removed
        ]

    def _som_collateral_effects(
        self,
        before: SecurityDescriptor,
        after: SecurityDescriptor,
        intended_principal: Principal,
        removed: tuple[Ace, ...],
    ) -> tuple[str, ...]:
        effects = self._removed_ace_effects(removed)
        for principal in self.environment.principals:
            if normalize_sid(principal.sid) == normalize_sid(intended_principal.sid):
                continue
            old = evaluate_access(
                before,
                principal.all_sids,
                ADS_RIGHT_DS_WRITE_PROP,
                GPLINK_GUID,
            ).decision
            new = evaluate_access(
                after,
                principal.all_sids,
                ADS_RIGHT_DS_WRITE_PROP,
                GPLINK_GUID,
            ).decision
            if old is not new:
                effects.append(
                    f"observed principal {principal.name}: WriteGPLink "
                    f"{old.value}->{new.value}"
                )
        return tuple(effects)

    def _gpo_collateral_effects(
        self,
        before: SecurityDescriptor,
        after: SecurityDescriptor,
        intended_target: Target,
        removed: tuple[Ace, ...],
    ) -> tuple[str, ...]:
        effects = self._removed_ace_effects(removed)
        for target in self.environment.targets:
            if normalize_sid(target.sid) == normalize_sid(intended_target.sid):
                continue
            before_pair = (
                evaluate_read_gpo(
                    before,
                    target.all_sids,
                    unresolved_token_sids=target.unresolved_sids,
                ).decision,
                evaluate_apply_gpo(
                    before,
                    target.all_sids,
                    unresolved_token_sids=target.unresolved_sids,
                ).decision,
            )
            after_pair = (
                evaluate_read_gpo(
                    after,
                    target.all_sids,
                    unresolved_token_sids=target.unresolved_sids,
                ).decision,
                evaluate_apply_gpo(
                    after,
                    target.all_sids,
                    unresolved_token_sids=target.unresolved_sids,
                ).decision,
            )
            if before_pair != after_pair:
                effects.append(
                    f"observed target {target.name}: Read/Apply "
                    f"{before_pair[0].value}/{before_pair[1].value}->"
                    f"{after_pair[0].value}/{after_pair[1].value}"
                )
        return tuple(effects)

    def _actions(
        self,
        environment: Environment,
        principal: Principal,
        target: Target,
        candidate: GPO,
        evaluation: Evaluation,
    ) -> tuple[Action, ...]:
        actions: list[Action] = []
        chain = evaluation.chain
        candidate_links = [
            item
            for item in evaluation.links
            if normalize_dn(item.link.gpo_dn) == normalize_dn(candidate.dn)
        ]

        for som in chain:
            som_caps = self._caps_som(principal, som)
            gplink_access = evaluate_access(
                som.security_descriptor,
                principal.all_sids,
                ADS_RIGHT_DS_WRITE_PROP,
                GPLINK_GUID,
            )
            write_dac_access = evaluate_access(
                som.security_descriptor, principal.all_sids, WRITE_DAC
            )
            already_linked = any(
                normalize_dn(link.gpo_dn) == normalize_dn(candidate.dn)
                for link in som.links
            )
            if Capability.WRITE_GPLINK in som_caps and not already_linked:
                actions.append(
                    Action(
                        ActionType.ADD_LINK,
                        Capability.WRITE_GPLINK,
                        f"Link {candidate.name} at order 1 on {som.dn}",
                        candidate.dn,
                        som.dn,
                        1,
                        authorization=gplink_access.evidence,
                    )
                )
            if (
                Capability.WRITE_SOM_SECURITY in som_caps
                and Capability.WRITE_GPLINK not in som_caps
            ):
                try:
                    _rewritten, removed, added = rewrite_write_gplink(
                        som.security_descriptor, principal.sid, principal.all_sids
                    )
                except UnsafeDaclRewriteError:
                    if self.explicit_blocker_rewrite:
                        _rewritten, removed, added = (
                            rewrite_write_gplink_explicit_blockers(
                            som.security_descriptor,
                            principal.sid,
                            principal.all_sids,
                        )
                        )
                        rewritten_gplink_access = evaluate_access(
                            _rewritten,
                            principal.all_sids,
                            ADS_RIGHT_DS_WRITE_PROP,
                            GPLINK_GUID,
                        )
                        if rewritten_gplink_access.decision is AccessDecision.ALLOW:
                            actions.append(
                                Action(
                                    ActionType.REWRITE_GPLINK_DACL,
                                    Capability.WRITE_SOM_SECURITY,
                                    f"Remove explicit DACL blockers on {som.dn} to grant "
                                    f"WriteGPLink to {principal.name}",
                                    candidate.dn,
                                    som.dn,
                                    target_sid=principal.sid,
                                    target_sids=(principal.sid,),
                                    authorization=write_dac_access.evidence,
                                    dacl_removed=removed,
                                    dacl_added=added,
                                    newly_exposed_rights=(
                                        f"WriteProperty:{GPLINK_GUID}",
                                    ),
                                    dacl_rewrite_mode=(
                                        DaclRewriteMode.EXPLICIT_BLOCKER_REWRITE
                                    ),
                                    collateral_trustees=(
                                        self._collateral_trustees(removed)
                                    ),
                                    collateral_effects=(
                                        self._som_collateral_effects(
                                            som.security_descriptor,
                                            _rewritten,
                                            principal,
                                            removed,
                                        )
                                    ),
                                )
                            )
                else:
                    rewritten_gplink_access = evaluate_access(
                        _rewritten,
                        principal.all_sids,
                        ADS_RIGHT_DS_WRITE_PROP,
                        GPLINK_GUID,
                    )
                    gplink_exposed = (
                        (f"WriteProperty:{GPLINK_GUID}",)
                        if gplink_access.decision is not AccessDecision.ALLOW
                        and rewritten_gplink_access.decision is AccessDecision.ALLOW
                        else ()
                    )
                    actions.append(
                        Action(
                            ActionType.GRANT_GPLINK,
                            Capability.WRITE_SOM_SECURITY,
                            f"Use WRITE_DAC on {som.dn} to grant WriteGPLink to {principal.name}",
                            candidate.dn,
                            som.dn,
                            target_sid=principal.sid,
                            target_sids=(principal.sid,),
                            authorization=write_dac_access.evidence,
                            dacl_removed=removed,
                            dacl_added=added,
                            newly_exposed_rights=gplink_exposed,
                            dacl_rewrite_mode=DaclRewriteMode.ADDITIVE_GRANT,
                        )
                    )

        for item in candidate_links:
            som_caps = self._caps_som(principal, item.som)
            if Capability.WRITE_GPLINK not in som_caps:
                continue
            gplink_evidence = evaluate_access(
                item.som.security_descriptor,
                principal.all_sids,
                ADS_RIGHT_DS_WRITE_PROP,
                GPLINK_GUID,
            ).evidence
            if item.link.disabled:
                actions.append(
                    Action(
                        ActionType.ENABLE_LINK,
                        Capability.WRITE_GPLINK,
                        f"Enable the {candidate.name} link on {item.som.dn}",
                        candidate.dn,
                        item.som.dn,
                        item.link.order,
                        authorization=gplink_evidence,
                    )
                )
            if item.link.order != 1:
                actions.append(
                    Action(
                        ActionType.REORDER_LINK,
                        Capability.WRITE_GPLINK,
                        f"Move {candidate.name} to link order 1 on {item.som.dn}",
                        candidate.dn,
                        item.som.dn,
                        item.link.order,
                        authorization=gplink_evidence,
                    )
                )
            if not item.link.enforced:
                actions.append(
                    Action(
                        ActionType.SET_ENFORCED,
                        Capability.WRITE_GPLINK,
                        f"Enforce the {candidate.name} link on {item.som.dn}",
                        candidate.dn,
                        item.som.dn,
                        item.link.order,
                        authorization=gplink_evidence,
                    )
                )

        for som in chain:
            if som.blocks_inheritance and Capability.WRITE_GPOPTIONS in self._caps_som(
                principal, som
            ):
                gpoptions_evidence = evaluate_access(
                    som.security_descriptor,
                    principal.all_sids,
                    ADS_RIGHT_DS_WRITE_PROP,
                    GPOPTIONS_GUID,
                ).evidence
                actions.append(
                    Action(
                        ActionType.CLEAR_BLOCK_INHERITANCE,
                        Capability.WRITE_GPOPTIONS,
                        f"Clear Block Inheritance on {som.dn}",
                        candidate.dn,
                        som.dn,
                        authorization=gpoptions_evidence,
                    )
                )

        gpo_caps = self._caps_gpo(principal, candidate)
        if Capability.WRITE_GPO_SECURITY in gpo_caps:
            write_dac_result = evaluate_access(
                candidate.security_descriptor, principal.all_sids, WRITE_DAC
            )
            before_read = evaluate_read_gpo(
                candidate.security_descriptor,
                target.all_sids,
                unresolved_token_sids=target.unresolved_sids,
            )
            before_apply = evaluate_apply_gpo(
                candidate.security_descriptor,
                target.all_sids,
                unresolved_token_sids=target.unresolved_sids,
            )
            try:
                _rewritten, removed, added = rewrite_read_apply(
                    candidate.security_descriptor, target.sid, target.all_sids
                )
            except UnsafeDaclRewriteError:
                if self.explicit_blocker_rewrite:
                    _rewritten, removed, added = (
                        rewrite_read_apply_explicit_blockers(
                        candidate.security_descriptor,
                        target.sid,
                        target.all_sids,
                    )
                    )
                    after_read = evaluate_read_gpo(
                        _rewritten,
                        target.all_sids,
                        unresolved_token_sids=target.unresolved_sids,
                    )
                    after_apply = evaluate_apply_gpo(
                        _rewritten,
                        target.all_sids,
                        unresolved_token_sids=target.unresolved_sids,
                    )
                    if (
                        after_read.decision is AccessDecision.ALLOW
                        and after_apply.decision is AccessDecision.ALLOW
                    ):
                        actions.append(
                            Action(
                                ActionType.REWRITE_READ_APPLY_DACL,
                                Capability.WRITE_GPO_SECURITY,
                                f"Remove explicit DACL blockers on {candidate.name} to "
                                f"grant Read and Apply Group Policy to {target.name}",
                                candidate.dn,
                                target_sid=target.sid,
                                target_sids=(target.sid,),
                                authorization=write_dac_result.evidence,
                                dacl_removed=removed,
                                dacl_added=added,
                                newly_exposed_rights=tuple(
                                    right
                                    for right, before, after in (
                                        ("DirectoryGenericRead", before_read, after_read),
                                        ("ApplyGroupPolicy", before_apply, after_apply),
                                    )
                                    if before.decision is not AccessDecision.ALLOW
                                    and after.decision is AccessDecision.ALLOW
                                ),
                                dacl_rewrite_mode=(
                                    DaclRewriteMode.EXPLICIT_BLOCKER_REWRITE
                                ),
                                collateral_trustees=(
                                    self._collateral_trustees(removed)
                                ),
                                collateral_effects=(
                                    self._gpo_collateral_effects(
                                        candidate.security_descriptor,
                                        _rewritten,
                                        target,
                                        removed,
                                    )
                                ),
                            )
                        )
            else:
                after_read = evaluate_read_gpo(
                    _rewritten,
                    target.all_sids,
                    unresolved_token_sids=target.unresolved_sids,
                )
                after_apply = evaluate_apply_gpo(
                    _rewritten,
                    target.all_sids,
                    unresolved_token_sids=target.unresolved_sids,
                )
                filter_exposed = tuple(
                    right
                    for right, before, after in (
                        ("DirectoryGenericRead", before_read, after_read),
                        ("ApplyGroupPolicy", before_apply, after_apply),
                    )
                    if before.decision is not AccessDecision.ALLOW
                    and after.decision is AccessDecision.ALLOW
                )
                actions.append(
                    Action(
                        ActionType.GRANT_READ_APPLY,
                        Capability.WRITE_GPO_SECURITY,
                        f"Grant Read and Apply Group Policy on {candidate.name} to {target.name}",
                        candidate.dn,
                        target_sid=target.sid,
                        target_sids=(target.sid,),
                        authorization=write_dac_result.evidence,
                        dacl_removed=removed,
                        dacl_added=added,
                        newly_exposed_rights=filter_exposed,
                        dacl_rewrite_mode=DaclRewriteMode.ADDITIVE_GRANT,
                    )
                )
        if candidate.computer_disabled and Capability.WRITE_GPO_CONTAINER in gpo_caps:
            flags_evidence = evaluate_access(
                candidate.security_descriptor,
                principal.all_sids,
                ADS_RIGHT_DS_WRITE_PROP,
                FLAGS_GUID,
            ).evidence
            actions.append(
                Action(
                    ActionType.ENABLE_COMPUTER_SECTION,
                    Capability.WRITE_GPO_CONTAINER,
                    f"Enable the computer section of {candidate.name}",
                    candidate.dn,
                    authorization=flags_evidence,
                )
            )
        return tuple({action.identity(): action for action in actions}.values())

    @staticmethod
    def _replace_link(environment: Environment, action: Action, transform) -> None:
        if not action.som_dn or not action.gpo_dn:
            raise ValueError("link action has no SOM/GPO")
        som = environment.som(action.som_dn)
        if som is None:
            raise KeyError(action.som_dn)
        links = tuple(
            transform(link)
            if normalize_dn(link.gpo_dn) == normalize_dn(action.gpo_dn)
            and link.order == action.link_order
            else link
            for link in som.links
        )
        environment.soms[normalize_dn(som.dn)] = replace(som, links=links)

    @classmethod
    def apply_action(cls, environment: Environment, action: Action) -> Environment:
        result = _clone(environment)
        if action.type is ActionType.ADD_LINK:
            som = result.som(action.som_dn or "")
            if som is None or not action.gpo_dn:
                raise KeyError(action.som_dn)
            links = (Link(action.gpo_dn, 0, 1),) + tuple(
                replace(link, order=index)
                for index, link in enumerate(
                    sorted(som.links, key=lambda item: item.order), start=2
                )
            )
            result.soms[normalize_dn(som.dn)] = replace(som, links=links)
        elif action.type is ActionType.ENABLE_LINK:
            cls._replace_link(result, action, lambda link: link.with_disabled(False))
        elif action.type is ActionType.SET_ENFORCED:
            cls._replace_link(result, action, lambda link: link.with_enforced(True))
        elif action.type is ActionType.REORDER_LINK:
            som = result.som(action.som_dn or "")
            if som is None or not action.gpo_dn or action.link_order is None:
                raise KeyError(action.som_dn)
            links = reorder_link(som.links, action.gpo_dn, action.link_order, 1)
            result.soms[normalize_dn(som.dn)] = replace(som, links=links)
        elif action.type is ActionType.CLEAR_BLOCK_INHERITANCE:
            som = result.som(action.som_dn or "")
            if som is None:
                raise KeyError(action.som_dn)
            result.soms[normalize_dn(som.dn)] = replace(
                som, gp_options=som.gp_options & ~0x1
            )
        elif action.type in {
            ActionType.GRANT_GPLINK,
            ActionType.REWRITE_GPLINK_DACL,
        }:
            som = result.som(action.som_dn or "")
            if som is None or not action.target_sid:
                raise KeyError(action.som_dn)
            actor = next(
                (
                    item
                    for item in result.principals
                    if normalize_sid(item.sid) == normalize_sid(action.target_sid or "")
                ),
                None,
            )
            token_sids = actor.all_sids if actor else (action.target_sid,)
            result.soms[normalize_dn(som.dn)] = replace(
                som,
                security_descriptor=(
                    rewrite_write_gplink_explicit_blockers(
                        som.security_descriptor, action.target_sid, token_sids
                    )[0]
                    if action.type is ActionType.REWRITE_GPLINK_DACL
                    else grant_write_gplink(
                        som.security_descriptor, action.target_sid, token_sids
                    )
                ),
            )
        elif action.type in {
            ActionType.GRANT_READ_APPLY,
            ActionType.REWRITE_READ_APPLY_DACL,
        }:
            gpo = result.gpo(action.gpo_dn or "")
            if gpo is None or not action.target_sid:
                raise KeyError(action.gpo_dn)
            target = next(
                (
                    item
                    for item in result.targets
                    if normalize_sid(item.sid) == normalize_sid(action.target_sid or "")
                ),
                None,
            )
            token_sids = target.all_sids if target else (action.target_sid,)
            result.gpos[normalize_dn(gpo.dn)] = replace(
                gpo,
                security_descriptor=(
                    rewrite_read_apply_explicit_blockers(
                        gpo.security_descriptor, action.target_sid, token_sids
                    )[0]
                    if action.type is ActionType.REWRITE_READ_APPLY_DACL
                    else grant_read_apply(
                        gpo.security_descriptor, action.target_sid, token_sids
                    )
                ),
            )
        elif action.type is ActionType.ENABLE_COMPUTER_SECTION:
            gpo = result.gpo(action.gpo_dn or "")
            if gpo is None:
                raise KeyError(action.gpo_dn)
            result.gpos[normalize_dn(gpo.dn)] = replace(gpo, flags=gpo.flags & ~0x2)
        else:
            raise NotImplementedError(action.type)
        return result

    def _successful_paths(
        self,
        principal: Principal,
        target: Target,
        candidate: GPO,
        setting: Setting,
    ) -> list[tuple[Action, ...]]:
        frontier: list[tuple[Environment, tuple[Action, ...]]] = [
            (self.environment, ())
        ]
        visited: set[tuple[tuple[object, ...], ...]] = set()
        for _depth in range(1, self.max_actions + 1):
            next_frontier: list[tuple[Environment, tuple[Action, ...]]] = []
            successes: list[tuple[Action, ...]] = []
            for state, path in frontier:
                evaluation = self._evaluate(state, target)
                current_candidate = state.gpo(candidate.dn)
                if current_candidate is None:
                    continue
                for action in self._actions(
                    state, principal, target, current_candidate, evaluation
                ):
                    if any(
                        action.identity() == existing.identity() for existing in path
                    ):
                        continue
                    new_path = path + (action,)
                    signature = tuple(item.identity() for item in new_path)
                    if signature in visited:
                        continue
                    visited.add(signature)
                    changed = self._apply_transition(state, action)
                    changed_gpo = changed.gpo(candidate.dn)
                    if changed_gpo and self._candidate_wins(
                        changed, target, changed_gpo, setting
                    ):
                        successes.append(new_path)
                    else:
                        next_frontier.append((changed, new_path))
            if successes:
                unique: dict[frozenset[tuple[object, ...]], tuple[Action, ...]] = {}
                for success in successes:
                    unique.setdefault(
                        frozenset(action.identity() for action in success), success
                    )
                return list(unique.values())
            frontier = next_frontier
        return []

    @staticmethod
    def _rank_paths(
        paths: list[tuple[Action, ...]],
    ) -> list[tuple[Action, ...]]:
        def sort_key(path: tuple[Action, ...]):
            return (
                len(path),
                tuple(
                    tuple(-1 if value is None else value for value in action.identity())
                    for action in path
                ),
            )

        return sorted(paths, key=sort_key)

    @staticmethod
    def _score(setting: Setting, target: Target, action_count: int) -> float:
        score = _SEVERITY_SCORE[setting.severity]
        if target.criticality.upper() in {"TIER0", "DOMAIN_CONTROLLER", "CRITICAL"}:
            score += 0.5
        score -= 0.55 * (action_count - 1)
        return round(max(0.0, min(10.0, score)), 1)

    @staticmethod
    def _finding_id(parts: Iterable[object]) -> str:
        material = json.dumps(list(parts), sort_keys=True, default=str).encode()
        return f"DORMANT-GPO-{hashlib.sha256(material).hexdigest()[:10].upper()}"

    def _dangerous_pairs(self) -> list[tuple[GPO, Setting]]:
        trusted_admin_sids: set[str] = set()
        if self.environment.domain_sid:
            trusted_admin_sids.add(f"{self.environment.domain_sid}-512")
        if self.environment.forest_root_sid:
            trusted_admin_sids.update(
                {
                    f"{self.environment.forest_root_sid}-518",
                    f"{self.environment.forest_root_sid}-519",
                }
            )
        pairs: list[tuple[GPO, Setting]] = []
        for gpo in self.environment.gpos.values():
            for original in gpo.settings:
                setting = assess_setting(original, trusted_admin_sids)
                if setting.dangerous:
                    pairs.append((gpo, setting))
        return pairs

    @staticmethod
    def _trustees(setting: Setting | None) -> frozenset[str]:
        if setting is None:
            return frozenset()
        values = (
            setting.value
            if isinstance(setting.value, (list, tuple, set))
            else ()
        )
        if setting.kind is SettingKind.RESTRICTED_GROUP:
            group, separator, relationship = setting.name.partition("/")
            if not separator:
                return frozenset()
            if relationship.casefold() == "memberof":
                memberships = {
                    normalize_sid(str(item).lstrip("*")) for item in values
                }
                return (
                    frozenset({normalize_sid(group.lstrip("*"))})
                    if "S-1-5-32-544" in memberships
                    else frozenset()
                )
            if relationship.casefold() != "members":
                return frozenset()
        elif setting.kind is not SettingKind.PRIVILEGE_RIGHT:
            return frozenset()
        return frozenset(normalize_sid(str(item).lstrip("*")) for item in values)

    @classmethod
    def _newly_privileged(
        cls, setting: Setting, current: EffectiveSetting | None
    ) -> tuple[str, ...]:
        candidates = (
            frozenset(setting.unexpected_trustees)
            if setting.unexpected_trustees
            else cls._trustees(setting)
        )
        return tuple(sorted(candidates - cls._trustees(current.setting if current else None)))

    def _referenced_sids(self) -> frozenset[str]:
        """Every trustee/owner SID named by any SOM or GPO security descriptor.

        A target's individual computer SID only ever changes an access decision
        if it is named here, so SIDs outside this set can be dropped from the
        target-grouping key without affecting results.
        """
        referenced: set[str] = set()
        for container in (self.environment.soms.values(), self.environment.gpos.values()):
            for item in container:
                descriptor = item.security_descriptor
                if descriptor.owner_sid:
                    referenced.add(normalize_sid(descriptor.owner_sid))
                for ace in descriptor.aces:
                    if ace.trustee_sid:
                        referenced.add(normalize_sid(ace.trustee_sid))
        for gpo in self.environment.gpos.values():
            referenced.update(normalize_sid(sid) for sid in gpo.file_acl_writable_sids)
        return frozenset(referenced)

    @staticmethod
    def _group_key(target: Target, referenced: frozenset[str]) -> tuple[object, ...]:
        relevant = frozenset(sid for sid in target.all_sids if sid in referenced)
        unresolved = frozenset(
            sid for sid in target.unresolved_sids if sid in referenced
        )
        return (
            normalize_dn(target.som_dn),
            normalize_dn(target.site_dn or ""),
            relevant,
            unresolved,
            target.criticality.upper(),
            target.token_incomplete,
            tuple(
                sorted((normalize_dn(filter_id), result) for filter_id, result in target.wmi_results)
            ),
            tuple(
                sorted(
                    (normalize_dn(gpo_id), decision.value)
                    for gpo_id, decision in target.gpt_read_decisions
                )
            ),
            tuple(
                sorted(
                    (
                        normalize_dn(observation.gpo_id),
                        observation.decision.value,
                    )
                    for observation in target.gpt_read_observations
                )
            ),
            target.site_resolution_error,
        )

    def _retarget_action(self, action: Action, targets: list[Target]) -> Action:
        """Attach the one claimed target to target-specific ACL actions."""
        if action.type in {
            ActionType.GRANT_READ_APPLY,
            ActionType.REWRITE_READ_APPLY_DACL,
        }:
            if len(targets) != 1:
                raise RuntimeError(
                    "target-specific ACL action cannot claim multiple targets"
                )
            target = targets[0]
            return replace(
                action,
                target_sid=target.sid,
                target_sids=(target.sid,),
            )
        return action

    def _path_wins(
        self,
        path: tuple[Action, ...],
        target: Target,
        candidate: GPO,
        setting: Setting,
    ) -> bool:
        """Replay a path from the pristine snapshot for one claimed target."""

        state = self.environment
        for action in path:
            state = self._apply_transition(state, action)
        changed_gpo = state.gpo(candidate.dn)
        return bool(
            changed_gpo
            and self._candidate_wins(state, target, changed_gpo, setting)
        )

    def _finding(
        self,
        principal: Principal,
        targets: list[Target],
        candidate: GPO,
        setting: Setting,
        reason: DormancyReason,
        winner: EffectiveSetting | None,
        paths: list[tuple[Action, ...]],
        evaluation: Evaluation,
        newly_privileged: tuple[str, ...],
    ) -> Finding:
        target = targets[0]
        for path in paths:
            for claimed_target in targets:
                if not self._path_wins(path, claimed_target, candidate, setting):
                    raise RuntimeError(
                        "finding replay invariant failed for "
                        f"{claimed_target.dn} and {candidate.dn}"
                    )
        raw_ranked = self._rank_paths(paths)
        raw_representative = raw_ranked[0]
        ranked = [
            tuple(self._retarget_action(action, targets) for action in path)
            for path in raw_ranked
        ]
        representative = ranked[0]
        alternatives = tuple(ranked[1:])
        capabilities = tuple(
            dict.fromkeys(
                action.capability for path in ranked for action in path
            )
        )
        requires_gpo_edit = any(
            action.type in _GPO_EDIT_ACTIONS for action in representative
        )
        final_state = self.environment
        counterfactual_trace: list[str] = []
        for index, action in enumerate(raw_representative, 1):
            final_state = self._apply_transition(final_state, action)
            step_evaluation = self._evaluate(final_state, target)
            counterfactual_trace.append(
                f"after action {index} ({action.type.value}):"
            )
            counterfactual_trace.extend(self._trace(step_evaluation))
        uncertainty_reasons: list[str] = []
        confidence_reasons = (
            "candidate path has not been differentially validated against "
            "Windows AuthZ/RSoP",
        )
        if principal.token_incomplete:
            uncertainty_reasons.append("principal token is incomplete")
        affected_unresolved = target.unresolved_sids.intersection(
            normalize_sid(ace.trustee_sid)
            for ace in candidate.security_descriptor.aces
            if ace.trustee_sid
        )
        if affected_unresolved:
            uncertainty_reasons.append(
                "target membership is unresolved for ACL trustee(s): "
                + ", ".join(sorted(affected_unresolved))
            )
        if target.token_incomplete and not target.unresolved_token_sids:
            uncertainty_reasons.append("legacy snapshot target token is incomplete")
        if (
            candidate.wmi_filter
            and target.wmi_result_for(candidate.wmi_filter) is None
        ):
            uncertainty_reasons.append("WMI filter result is unknown for this target")
        if candidate.version_number != candidate.gpt_version and None not in {
            candidate.version_number,
            candidate.gpt_version,
        }:
            uncertainty_reasons.append("AD and GPT versions diverge")
        uncertainty_reasons.extend(evaluation.uncertainty_reasons_for(setting))
        gpt_access_provenance = tuple(
            GptAccessProvenance(
                claimed_target.name,
                claimed_target.sid,
                observation.authenticated_sid,
                observation.credential_principal,
                observation.identity_attestation,
                observation.decision_for(setting.kind),
                observation.source,
                observation.oracle,
                observation.oracle_version,
                observation.observed_at,
                observation.snapshot_sha256,
                observation.dc,
                observation.token_sids_sha256,
            )
            for claimed_target in targets
            for observation in claimed_target.gpt_read_observations
            if candidate.matches_identifier(observation.gpo_id)
        )
        return Finding(
            finding_id="",
            principal=principal.name,
            principal_sid=principal.sid,
            capability=representative[0].capability,
            capabilities=capabilities,
            gpo_name=candidate.name,
            gpo_dn=candidate.dn,
            setting_kind=setting.kind,
            setting_name=setting.name,
            dormant_value=setting.value,
            reason=reason,
            current_winner=winner.gpo.name if winner else None,
            actions=representative,
            alternative_paths=alternatives,
            targets=[item.name for item in targets],
            target_dns=[item.dn for item in targets],
            result_value=setting.value,
            severity=setting.severity,
            score=max(
                self._score(setting, item, len(representative)) for item in targets
            ),
            requires_gpo_edit=requires_gpo_edit,
            confidence=Confidence.LOW,
            confidence_reasons=confidence_reasons,
            uncertainty_reasons=tuple(dict.fromkeys(uncertainty_reasons)),
            rule_id=setting.risk_rule_id,
            current_value=winner.setting.value if winner else None,
            value_sensitivity=setting.value_sensitivity,
            current_value_sensitivity=(
                winner.setting.value_sensitivity if winner else setting.value_sensitivity
            ),
            newly_privileged_trustees=newly_privileged,
            target_role=target.criticality,
            current_processing_trace=self._trace(evaluation),
            counterfactual_trace=tuple(counterfactual_trace),
            ad_version=candidate.version_number,
            gpt_version=candidate.gpt_version,
            usn_changed=candidate.usn_changed,
            gpt_hashes=candidate.gpt_hashes,
            sysvol_readable=(
                target.gpt_read_decision_for(candidate, setting.kind)
                is AccessDecision.ALLOW
                or (
                    target.gpt_read_decision_for(candidate, setting.kind) is None
                    and self.environment.collected_at is None
                    and candidate.gpt_readable
                )
            ),
            collector_sysvol_readable=candidate.collector_gpt_readable,
            gpt_access_provenance=gpt_access_provenance,
        )

    def _record_gap(
        self,
        principal: Principal,
        target: Target,
        candidate: GPO,
        gate: str,
        reason: str,
    ) -> None:
        key = (
            principal.sid,
            target.dn,
            candidate.dn,
            gate,
            reason,
        )
        gap_id = self._finding_id(("coverage-gap", *key)).replace(
            "DORMANT-GPO-", "COVERAGE-GAP-"
        )
        if key in self._coverage_gap_keys:
            return
        if len(self.coverage_gaps) >= self.max_coverage_gaps:
            raise WorkBudgetExceeded(
                f"coverage-gap budget exceeded ({self.max_coverage_gaps}); narrow the "
                "scan or raise --max-coverage-gaps"
            )
        self._coverage_gap_keys.add(key)
        gap = CoverageGap(
            gap_id=gap_id,
            principal=principal.name,
            principal_sid=principal.sid,
            gpo_name=candidate.name,
            gpo_dn=candidate.dn,
            target=target.name,
            target_dn=target.dn,
            gate=gate,
            reason=reason,
        )
        self.coverage_gaps.append(gap)

    def _coverage_reason(
        self,
        principal: Principal,
        target: Target,
        candidate: GPO,
        setting: Setting,
        evaluation: Evaluation,
    ) -> tuple[str, str] | None:
        if principal.token_incomplete:
            return "ACTOR_TOKEN", "principal tokenGroups could not be fully resolved"
        if target.token_incomplete and not target.unresolved_token_sids:
            return (
                "TARGET_TOKEN",
                "legacy snapshot has only an all-or-nothing incomplete target token",
            )
        if candidate.settings_incomplete_for(setting.kind):
            return (
                "GPT_SETTINGS",
                "; ".join(candidate.settings_uncertainty_reasons)
                or "supported GPT policy files were not fully collected",
            )
        if (
            candidate.functionality_version is None
            and self.environment.collected_at is not None
        ):
            return (
                "GPO_METADATA",
                "gPCFunctionalityVersion was not returned during collection",
            )
        target_gpt_read = target.gpt_read_decision_for(candidate, setting.kind)
        if target_gpt_read is AccessDecision.UNKNOWN or (
            target_gpt_read is None and self.environment.collected_at is not None
        ):
            return (
                "TARGET_GPT_READ",
                "target GPT read authorization was not deterministically established",
            )
        if candidate.machine_extensions is None and setting.required_extension:
            return (
                "CSE_ADVERTISEMENT",
                "machine CSE advertisement was not collected",
            )
        if candidate.wmi_filter:
            observed = target.wmi_result_for(candidate.wmi_filter)
            if observed is False or (
                observed is None and candidate.wmi_result is False
            ):
                return (
                    "WMI_MUTATION_UNSUPPORTED",
                    "the WMI filter evaluated false and GPOWake does not model "
                    "a mutation that can make the filter true",
                )
            if observed is None and candidate.wmi_result is not False:
                return (
                    "WMI_FILTER",
                    "WMI filter result was not evaluated for this target",
                )
        for item in evaluation.links:
            if (
                normalize_dn(item.link.gpo_dn) == normalize_dn(candidate.dn)
                and item.uncertain
            ):
                gate = {
                    "WMI_FILTERED": "WMI_FILTER",
                    "SECURITY_FILTERED": "SECURITY_FILTER",
                    "GPT_UNREADABLE": "TARGET_GPT_READ",
                    "GPO_MISSING": "GPO_COLLECTION",
                }.get(item.status.value, "POLICY_GATE")
                return gate, item.detail or "policy applicability is unknown"
        relevant_uncertainties = evaluation.uncertainties_for(setting)
        if relevant_uncertainties:
            return (
                relevant_uncertainties[0].gate,
                "; ".join(
                    dict.fromkeys(item.reason for item in relevant_uncertainties)
                ),
            )
        read_result = evaluate_read_gpo(
            candidate.security_descriptor,
            target.all_sids,
            unresolved_token_sids=target.unresolved_sids,
        )
        apply_result = evaluate_apply_gpo(
            candidate.security_descriptor,
            target.all_sids,
            unresolved_token_sids=target.unresolved_sids,
        )
        if AccessDecision.UNKNOWN in {
            read_result.decision,
            apply_result.decision,
        }:
            return (
                "SECURITY_FILTER",
                "; ".join(
                    (
                        *read_result.uncertainty_reasons,
                        *apply_result.uncertainty_reasons,
                    )
                )
                or "target security-filter authorization is unknown",
            )
        return None

    @staticmethod
    def _trace_value(setting: Setting) -> str:
        safe = redact_value(setting.value, setting.value_sensitivity)
        rendered = json.dumps(safe, sort_keys=True, default=str, ensure_ascii=True)
        if len(rendered) <= _MAX_TRACE_VALUE_CHARS:
            return rendered
        digest = hashlib.sha256(rendered.encode("utf-8")).hexdigest()[:12]
        return (
            f"<{type(safe).__name__} chars={len(rendered)} "
            f"sha256={digest}>"
        )

    @staticmethod
    def _bounded_trace_line(line: str) -> str:
        if len(line) <= _MAX_TRACE_LINE_CHARS:
            return line
        digest = hashlib.sha256(line.encode("utf-8")).hexdigest()[:12]
        suffix = f"... <truncated chars={len(line)} sha256={digest}>"
        return line[: _MAX_TRACE_LINE_CHARS - len(suffix)] + suffix

    @staticmethod
    def _trace(evaluation: Evaluation) -> tuple[str, ...]:
        lines = [
            CounterfactualSolver._bounded_trace_line(
                f"{item.som.kind.value}:{item.som.dn} order={item.link.order} "
                f"enforced={item.link.enforced} disabled={item.link.disabled} "
                f"gpo={item.link.gpo_dn} status={item.status.value}"
                + (f" detail={item.detail}" if item.detail else "")
            )
            for item in evaluation.links
        ]
        lines.extend(
            CounterfactualSolver._bounded_trace_line(
                f"winner {kind}/{name}: {winner.gpo.name} "
                f"value={CounterfactualSolver._trace_value(winner.setting)}"
            )
            for (kind, name), winner in sorted(evaluation.winners.items())
        )
        return tuple(lines)

    def solve(self) -> list[Finding]:
        self.coverage_gaps = []
        self._coverage_gap_keys = set()
        self.candidate_evaluations = 0
        self.transition_evaluations = 0
        dangerous = self._dangerous_pairs()
        if not dangerous:
            incomplete_gpos = [
                gpo for gpo in self.environment.gpos.values() if not gpo.settings_complete
            ]
            for principal in self.environment.principals:
                for target in self.environment.targets:
                    for gpo in incomplete_gpos:
                        self._record_gap(
                            principal,
                            target,
                            gpo,
                            "GPT_SETTINGS",
                            "; ".join(gpo.settings_uncertainty_reasons)
                            or "supported GPT policy files were not collected",
                        )
            return []
        referenced = self._referenced_sids()
        groups: dict[tuple[object, ...], list[Target]] = {}
        for target in self.environment.targets:
            groups.setdefault(self._group_key(target, referenced), []).append(target)

        raw: list[Finding] = []
        for principal in self.environment.principals:
            for members in groups.values():
                representative_target = members[0]
                evaluation = self._evaluate(self.environment, representative_target)
                for candidate, setting in dangerous:
                    self.candidate_evaluations += 1
                    if self.candidate_evaluations > self.max_candidate_evaluations:
                        raise WorkBudgetExceeded(
                            "candidate-evaluation budget exceeded "
                            f"({self.max_candidate_evaluations}); narrow --principal/--target, "
                            "raise --max-candidates, or run --estimate-only"
                        )
                    relevant_uncertainties = evaluation.uncertainties_for(setting)
                    if relevant_uncertainties and not (
                        self._uncertainties_can_be_replayed_after_dacl_rewrite(
                            relevant_uncertainties, candidate
                        )
                    ):
                        initial_coverage = self._coverage_reason(
                            principal,
                            representative_target,
                            candidate,
                            setting,
                            evaluation,
                        ) or (
                            "POLICY_INPUT",
                            "; ".join(
                                dict.fromkeys(
                                    item.reason for item in relevant_uncertainties
                                )
                            ),
                        )
                        self._record_gap(
                            principal,
                            representative_target,
                            candidate,
                            *initial_coverage,
                        )
                        continue
                    current = evaluation.winners.get(setting.key)
                    if (
                        not relevant_uncertainties
                        and (
                            (
                                PolicyEngine.is_restricted_member_of(setting)
                                and any(
                                    not contributor.uncertain
                                    and normalize_dn(contributor.gpo.dn)
                                    == normalize_dn(candidate.dn)
                                    and contributor.setting.value == setting.value
                                    for contributor in evaluation.additive_contributors.get(
                                        setting.key, ()
                                    )
                                )
                            )
                            or (
                                not PolicyEngine.is_restricted_member_of(setting)
                                and current
                                and not current.uncertain
                                and normalize_dn(current.gpo.dn)
                                == normalize_dn(candidate.dn)
                                and current.setting.value == setting.value
                            )
                        )
                    ):
                        continue
                    newly_privileged = self._newly_privileged(setting, current)
                    if (
                        setting.kind
                        in {
                            SettingKind.PRIVILEGE_RIGHT,
                            SettingKind.RESTRICTED_GROUP,
                        }
                        and not newly_privileged
                    ):
                        continue
                    paths = self._successful_paths(
                        principal, representative_target, candidate, setting
                    )
                    if not paths:
                        missing_path_coverage = self._coverage_reason(
                            principal,
                            representative_target,
                            candidate,
                            setting,
                            evaluation,
                        )
                        if missing_path_coverage:
                            self._record_gap(
                                principal,
                                representative_target,
                                candidate,
                                *missing_path_coverage,
                            )
                        continue
                    common_paths = [
                        path
                        for path in paths
                        if all(
                            self._path_wins(path, member, candidate, setting)
                            for member in members
                        )
                    ]
                    target_sets = [members] if common_paths else [[item] for item in members]
                    for claimed_targets in target_sets:
                        claimed_target = claimed_targets[0]
                        claimed_evaluation = self._evaluate(
                            self.environment, claimed_target
                        )
                        claimed_paths = common_paths
                        if not claimed_paths:
                            claimed_paths = [
                                path
                                for path in self._successful_paths(
                                    principal, claimed_target, candidate, setting
                                )
                                if self._path_wins(
                                    path, claimed_target, candidate, setting
                                )
                            ]
                        if not claimed_paths:
                            target_coverage = self._coverage_reason(
                                principal,
                                claimed_target,
                                candidate,
                                setting,
                                claimed_evaluation,
                            )
                            if target_coverage:
                                self._record_gap(
                                    principal,
                                    claimed_target,
                                    candidate,
                                    *target_coverage,
                                )
                            continue
                        claimed_current = claimed_evaluation.winners.get(setting.key)
                        claimed_new = self._newly_privileged(setting, claimed_current)
                        reason, winner = PolicyEngine(
                            self.environment
                        ).dormancy_reason(
                            claimed_evaluation, candidate, setting
                        )
                        if len(raw) >= self.max_findings:
                            raise WorkBudgetExceeded(
                                f"finding budget exceeded ({self.max_findings}); narrow the "
                                "scan or raise --max-findings"
                            )
                        raw.append(
                            self._finding(
                                principal,
                                claimed_targets,
                                candidate,
                                setting,
                                reason,
                                winner,
                                claimed_paths,
                                claimed_evaluation,
                                claimed_new,
                            )
                        )
        return self._group(raw)

    @staticmethod
    def _path_signature(finding: Finding) -> frozenset[frozenset[tuple[object, ...]]]:
        return frozenset(
            frozenset(action.identity() for action in path) for path in finding.paths
        )

    @classmethod
    def _group(cls, findings: list[Finding]) -> list[Finding]:
        result = list(findings)
        for finding in result:
            finding.targets = sorted(set(finding.targets))
            finding.target_dns = sorted(set(finding.target_dns))
            finding.score = round(
                min(
                    10.0,
                    finding.score
                    + min(0.5, math.log2(max(1, len(finding.targets))) * 0.1),
                ),
                1,
            )
            finding.finding_id = cls._finding_id(
                (
                    finding.principal_sid,
                    finding.gpo_dn,
                    finding.setting_kind.value,
                    finding.setting_name,
                    finding.dormant_value,
                    finding.current_value,
                    finding.current_winner,
                    finding.newly_privileged_trustees,
                    finding.reason.value,
                    sorted(
                        sorted(str(item) for item in path)
                        for path in cls._path_signature(finding)
                    ),
                    tuple(finding.target_dns),
                )
            )
        return sorted(result, key=lambda item: (-item.score, item.finding_id))
