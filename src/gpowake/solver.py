from __future__ import annotations

import copy
import hashlib
import json
import math
from dataclasses import replace
from typing import Iterable

from .acl import capabilities_on_gpo, capabilities_on_som, grant_read_apply
from .gplink import reorder_link
from .models import (
    Action,
    ActionType,
    Capability,
    Environment,
    Finding,
    GPO,
    Link,
    Principal,
    Severity,
    Setting,
    Target,
    normalize_dn,
)
from .precedence import Evaluation, PolicyEngine


_SEVERITY_SCORE = {
    Severity.LOW: 3.0,
    Severity.MEDIUM: 5.5,
    Severity.HIGH: 8.0,
    Severity.CRITICAL: 9.3,
}


class CounterfactualSolver:
    def __init__(self, environment: Environment, max_actions: int = 1):
        if max_actions < 1 or max_actions > 2:
            raise ValueError("max_actions must be 1 or 2")
        self.environment = environment
        self.max_actions = max_actions

    @staticmethod
    def _candidate_wins(
        environment: Environment, target: Target, gpo: GPO, setting: Setting
    ) -> bool:
        winner = PolicyEngine(environment).evaluate(target).winners.get(setting.key)
        return (
            winner is not None
            and normalize_dn(winner.gpo.dn) == normalize_dn(gpo.dn)
            and winner.setting.value == setting.value
        )

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
        local_som = environment.som(target.som_dn)
        if local_som and Capability.WRITE_GPLINK in capabilities_on_som(
            principal, local_som
        ):
            already_local = any(
                normalize_dn(item.gpo_dn) == normalize_dn(candidate.dn)
                for item in local_som.links
            )
            if not already_local:
                actions.append(
                    Action(
                        ActionType.ADD_LINK,
                        Capability.WRITE_GPLINK,
                        f"Link {candidate.name} at order 1 on {local_som.dn}",
                        candidate.dn,
                        local_som.dn,
                        1,
                    )
                )

        for item in candidate_links:
            som_caps = capabilities_on_som(principal, item.som)
            if Capability.WRITE_GPLINK not in som_caps:
                continue
            if item.link.disabled:
                actions.append(
                    Action(
                        ActionType.ENABLE_LINK,
                        Capability.WRITE_GPLINK,
                        f"Enable the {candidate.name} link on {item.som.dn}",
                        candidate.dn,
                        item.som.dn,
                        item.link.order,
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
                    )
                )

        for som in chain:
            if (
                som.blocks_inheritance
                and Capability.WRITE_GPOPTIONS in capabilities_on_som(principal, som)
            ):
                actions.append(
                    Action(
                        ActionType.CLEAR_BLOCK_INHERITANCE,
                        Capability.WRITE_GPOPTIONS,
                        f"Clear Block Inheritance on {som.dn}",
                        candidate.dn,
                        som.dn,
                    )
                )

        gpo_caps = capabilities_on_gpo(principal, candidate)
        if Capability.WRITE_GPO_SECURITY in gpo_caps:
            actions.append(
                Action(
                    ActionType.GRANT_READ_APPLY,
                    Capability.WRITE_GPO_SECURITY,
                    f"Grant Read and Apply Group Policy on {candidate.name} to {target.name}",
                    candidate.dn,
                    target_sid=target.sid,
                )
            )
        if candidate.computer_disabled and Capability.WRITE_GPO_CONTAINER in gpo_caps:
            actions.append(
                Action(
                    ActionType.ENABLE_COMPUTER_SECTION,
                    Capability.WRITE_GPO_CONTAINER,
                    f"Enable the computer section of {candidate.name}",
                    candidate.dn,
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
        result = copy.deepcopy(environment)
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
        elif action.type is ActionType.GRANT_READ_APPLY:
            gpo = result.gpo(action.gpo_dn or "")
            if gpo is None or not action.target_sid:
                raise KeyError(action.gpo_dn)
            result.gpos[normalize_dn(gpo.dn)] = replace(
                gpo,
                security_descriptor=grant_read_apply(
                    gpo.security_descriptor, action.target_sid
                ),
            )
        elif action.type is ActionType.ENABLE_COMPUTER_SECTION:
            gpo = result.gpo(action.gpo_dn or "")
            if gpo is None:
                raise KeyError(action.gpo_dn)
            result.gpos[normalize_dn(gpo.dn)] = replace(gpo, flags=gpo.flags & ~0x2)
        else:  # pragma: no cover - future action type guard
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
                evaluation = PolicyEngine(state).evaluate(target)
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
                    changed = self.apply_action(state, action)
                    changed_gpo = changed.gpo(candidate.dn)
                    if changed_gpo and self._candidate_wins(
                        changed, target, changed_gpo, setting
                    ):
                        successes.append(new_path)
                    else:
                        next_frontier.append((changed, new_path))
            if successes:
                # Independent writes can be explored in both orders. They are one
                # state-transition path for reporting purposes, not two findings.
                unique: dict[frozenset[tuple[object, ...]], tuple[Action, ...]] = {}
                for success in successes:
                    unique.setdefault(
                        frozenset(action.identity() for action in success), success
                    )
                return list(unique.values())
            frontier = next_frontier
        return []

    @staticmethod
    def _confidence(
        environment: Environment, target: Target, gpo: GPO, evaluation: Evaluation
    ) -> str:
        low = gpo.wmi_filter is not None and gpo.wmi_result is None
        low = low or bool(gpo.security_descriptor.collection_error)
        uncertain = low or any(
            item.uncertain
            for item in evaluation.links
            if normalize_dn(item.link.gpo_dn) == normalize_dn(gpo.dn)
        )
        version_mismatch = (
            gpo.version_number is not None
            and gpo.gpt_version is not None
            and gpo.version_number != gpo.gpt_version
        )
        site_unknown = any(
            "site" in warning.casefold() and target.name in warning
            for warning in environment.warnings
        )
        if uncertain:
            return "LOW"
        if version_mismatch or site_unknown:
            return "MEDIUM"
        return "HIGH"

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

    def solve(self) -> list[Finding]:
        raw: list[Finding] = []
        for principal in self.environment.principals:
            for target in self.environment.targets:
                evaluation = PolicyEngine(self.environment).evaluate(target)
                for candidate in self.environment.gpos.values():
                    for setting in candidate.settings:
                        if not setting.dangerous:
                            continue
                        current = evaluation.winners.get(setting.key)
                        if (
                            current
                            and normalize_dn(current.gpo.dn)
                            == normalize_dn(candidate.dn)
                            and current.setting.value == setting.value
                        ):
                            continue
                        reason, winner = PolicyEngine(self.environment).dormancy_reason(
                            evaluation, candidate, setting
                        )
                        for actions in self._successful_paths(
                            principal, target, candidate, setting
                        ):
                            identity = (
                                principal.sid,
                                candidate.dn,
                                setting.key,
                                reason.value,
                                tuple(action.identity() for action in actions),
                                target.sid,
                            )
                            raw.append(
                                Finding(
                                    finding_id=self._finding_id(identity),
                                    principal=principal.name,
                                    principal_sid=principal.sid,
                                    capability=actions[0].capability,
                                    capabilities=tuple(
                                        dict.fromkeys(
                                            action.capability for action in actions
                                        )
                                    ),
                                    gpo_name=candidate.name,
                                    gpo_dn=candidate.dn,
                                    setting_kind=setting.kind,
                                    setting_name=setting.name,
                                    dormant_value=setting.value,
                                    reason=reason,
                                    current_winner=winner.gpo.name if winner else None,
                                    actions=actions,
                                    targets=[target.name],
                                    target_dns=[target.dn],
                                    result_value=setting.value,
                                    severity=setting.severity,
                                    score=self._score(setting, target, len(actions)),
                                    confidence=self._confidence(
                                        self.environment, target, candidate, evaluation
                                    ),
                                    requires_gpo_edit=any(
                                        action.type
                                        in {
                                            ActionType.GRANT_READ_APPLY,
                                            ActionType.ENABLE_COMPUTER_SECTION,
                                        }
                                        for action in actions
                                    ),
                                )
                            )
        return self._group(raw)

    @staticmethod
    def _group(findings: list[Finding]) -> list[Finding]:
        grouped: dict[tuple[object, ...], Finding] = {}
        for finding in findings:
            key = (
                finding.principal_sid,
                normalize_dn(finding.gpo_dn),
                finding.setting_kind.value,
                finding.setting_name.casefold(),
                finding.reason.value,
                finding.current_winner,
                tuple(action.identity() for action in finding.actions),
            )
            existing = grouped.get(key)
            if existing is None:
                grouped[key] = finding
                continue
            existing.targets.extend(finding.targets)
            existing.target_dns.extend(finding.target_dns)
            existing.score = max(existing.score, finding.score)
            if finding.confidence == "LOW" or (
                finding.confidence == "MEDIUM" and existing.confidence == "HIGH"
            ):
                existing.confidence = finding.confidence
        result = list(grouped.values())
        for finding in result:
            finding.targets = sorted(set(finding.targets))
            finding.target_dns = sorted(set(finding.target_dns))
            # A small bounded blast-radius bonus, applied only after grouping.
            finding.score = round(
                min(
                    10.0,
                    finding.score
                    + min(0.5, math.log2(max(1, len(finding.targets))) * 0.1),
                ),
                1,
            )
            finding.finding_id = CounterfactualSolver._finding_id(
                (
                    finding.principal_sid,
                    finding.gpo_dn,
                    finding.setting_kind.value,
                    finding.setting_name,
                    finding.reason.value,
                    tuple(action.identity() for action in finding.actions),
                    tuple(finding.target_dns),
                )
            )
        return sorted(result, key=lambda item: (-item.score, item.finding_id))
