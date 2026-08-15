from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .acl import can_apply_gpo, can_read_gpo
from .models import (
    DormancyReason,
    Environment,
    GPO,
    Link,
    ScopeOfManagement,
    Setting,
    Target,
    normalize_dn,
)


class LinkStatus(str, Enum):
    APPLIES = "APPLIES"
    DISABLED = "DISABLED"
    BLOCKED = "BLOCKED"
    GPO_MISSING = "GPO_MISSING"
    SECTION_DISABLED = "SECTION_DISABLED"
    SECURITY_FILTERED = "SECURITY_FILTERED"
    WMI_FILTERED = "WMI_FILTERED"
    GPT_UNREADABLE = "GPT_UNREADABLE"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True)
class LinkEvaluation:
    som: ScopeOfManagement
    link: Link
    scope_index: int
    status: LinkStatus
    uncertain: bool = False
    detail: str = ""


@dataclass(frozen=True)
class EffectiveSetting:
    setting: Setting
    gpo: GPO
    application: LinkEvaluation
    uncertain: bool = False


@dataclass(frozen=True)
class Evaluation:
    target: Target
    chain: tuple[ScopeOfManagement, ...]
    links: tuple[LinkEvaluation, ...]
    processing_order: tuple[LinkEvaluation, ...]
    winners: dict[tuple[str, str], EffectiveSetting]


class PolicyEngine:
    """Evaluate deterministic computer-side policy ordering for one target."""

    def __init__(self, environment: Environment):
        self.environment = environment

    def som_chain(self, target: Target) -> tuple[ScopeOfManagement, ...]:
        chain: list[ScopeOfManagement] = []
        seen: set[str] = set()
        current = self.environment.som(target.som_dn)
        while current is not None:
            key = normalize_dn(current.dn)
            if key in seen:
                raise ValueError(f"cycle in SOM hierarchy at {current.dn}")
            seen.add(key)
            chain.append(current)
            current = (
                self.environment.som(current.parent_dn) if current.parent_dn else None
            )
        chain.reverse()
        if target.site_dn:
            site = self.environment.som(target.site_dn)
            if site is not None and normalize_dn(site.dn) not in seen:
                chain.insert(0, site)
        return tuple(chain)

    def _link_status(
        self,
        target: Target,
        chain: tuple[ScopeOfManagement, ...],
        scope_index: int,
        som: ScopeOfManagement,
        link: Link,
    ) -> LinkEvaluation:
        if link.disabled:
            return LinkEvaluation(som, link, scope_index, LinkStatus.DISABLED)
        blocking = next(
            (item for item in chain[scope_index + 1 :] if item.blocks_inheritance), None
        )
        if blocking is not None and not link.enforced:
            return LinkEvaluation(
                som,
                link,
                scope_index,
                LinkStatus.BLOCKED,
                detail=f"blocked by {blocking.dn}",
            )
        gpo = self.environment.gpo(link.gpo_dn)
        if gpo is None:
            return LinkEvaluation(som, link, scope_index, LinkStatus.GPO_MISSING)
        if gpo.functionality_version is not None and gpo.functionality_version != 2:
            return LinkEvaluation(
                som,
                link,
                scope_index,
                LinkStatus.UNSUPPORTED,
                detail=f"unsupported gPCFunctionalityVersion {gpo.functionality_version}",
            )
        if not gpo.gpt_readable:
            return LinkEvaluation(som, link, scope_index, LinkStatus.GPT_UNREADABLE)
        if gpo.computer_disabled:
            return LinkEvaluation(som, link, scope_index, LinkStatus.SECTION_DISABLED)
        uncertain = False
        detail = ""
        if gpo.security_descriptor.collection_error:
            return LinkEvaluation(
                som,
                link,
                scope_index,
                LinkStatus.SECURITY_FILTERED,
                uncertain=True,
                detail=gpo.security_descriptor.collection_error,
            )
        elif not (
            can_read_gpo(gpo.security_descriptor, target.all_sids)
            and can_apply_gpo(gpo.security_descriptor, target.all_sids)
        ):
            return LinkEvaluation(som, link, scope_index, LinkStatus.SECURITY_FILTERED)
        if gpo.wmi_filter:
            if gpo.wmi_result is False:
                return LinkEvaluation(som, link, scope_index, LinkStatus.WMI_FILTERED)
            if gpo.wmi_result is None:
                return LinkEvaluation(
                    som,
                    link,
                    scope_index,
                    LinkStatus.WMI_FILTERED,
                    uncertain=True,
                    detail="WMI filter result was not evaluated",
                )
        return LinkEvaluation(
            som, link, scope_index, LinkStatus.APPLIES, uncertain, detail
        )

    @staticmethod
    def _processing_key(item: LinkEvaluation) -> tuple[int, int, int]:
        # Normal links: site/domain/OU from broad to specific, and high numeric
        # link order first so order 1 is processed last. Enforced links are then
        # processed from the deepest scope toward the root; root enforcement wins.
        if item.link.enforced:
            return 1, -item.scope_index, -item.link.order
        return 0, item.scope_index, -item.link.order

    def evaluate(self, target: Target) -> Evaluation:
        chain = self.som_chain(target)
        links = tuple(
            self._link_status(target, chain, scope_index, som, link)
            for scope_index, som in enumerate(chain)
            for link in sorted(som.links, key=lambda item: item.order)
        )
        processing = tuple(
            sorted(
                (item for item in links if item.status is LinkStatus.APPLIES),
                key=self._processing_key,
            )
        )
        winners: dict[tuple[str, str], EffectiveSetting] = {}
        for application in processing:
            gpo = self.environment.gpo(application.link.gpo_dn)
            if gpo is None:
                continue
            for setting in gpo.settings:
                extension_uncertain = False
                if setting.required_extension and gpo.machine_extensions is not None:
                    advertised = {
                        value.strip("{}").casefold() for value in gpo.machine_extensions
                    }
                    if (
                        setting.required_extension.strip("{}").casefold()
                        not in advertised
                    ):
                        continue
                elif setting.required_extension and gpo.machine_extensions is None:
                    extension_uncertain = True
                winners[setting.key] = EffectiveSetting(
                    setting=setting,
                    gpo=gpo,
                    application=application,
                    uncertain=application.uncertain or extension_uncertain,
                )
        return Evaluation(target, chain, links, processing, winners)

    def dormancy_reason(
        self,
        evaluation: Evaluation,
        candidate: GPO,
        setting: Setting,
    ) -> tuple[DormancyReason, EffectiveSetting | None]:
        candidate_links = [
            item
            for item in evaluation.links
            if normalize_dn(item.link.gpo_dn) == normalize_dn(candidate.dn)
        ]
        if not candidate_links:
            return DormancyReason.UNLINKED, evaluation.winners.get(setting.key)
        statuses = {item.status for item in candidate_links}
        if LinkStatus.APPLIES not in statuses:
            priority = (
                (LinkStatus.DISABLED, DormancyReason.LINK_DISABLED),
                (LinkStatus.BLOCKED, DormancyReason.BLOCKED_INHERITANCE),
                (LinkStatus.SECTION_DISABLED, DormancyReason.SECTION_DISABLED),
                (LinkStatus.SECURITY_FILTERED, DormancyReason.SECURITY_FILTERED),
                (LinkStatus.WMI_FILTERED, DormancyReason.WMI_FILTERED),
                (LinkStatus.GPT_UNREADABLE, DormancyReason.GPT_UNREADABLE),
            )
            for status, reason in priority:
                if status in statuses:
                    return reason, evaluation.winners.get(setting.key)
            return DormancyReason.UNLINKED, evaluation.winners.get(setting.key)
        if candidate.computer_disabled:
            return DormancyReason.SECTION_DISABLED, evaluation.winners.get(setting.key)
        if setting.required_extension and candidate.machine_extensions is not None:
            advertised = {
                value.strip("{}").casefold() for value in candidate.machine_extensions
            }
            if setting.required_extension.strip("{}").casefold() not in advertised:
                return DormancyReason.EXTENSION_MISSING, evaluation.winners.get(
                    setting.key
                )

        winner = evaluation.winners.get(setting.key)
        if winner is None:
            return DormancyReason.OVERRIDDEN_SETTING, None
        candidate_apps = [
            item
            for item in evaluation.processing_order
            if normalize_dn(item.link.gpo_dn) == normalize_dn(candidate.dn)
        ]
        candidate_app = candidate_apps[-1] if candidate_apps else None
        if candidate_app and normalize_dn(candidate_app.som.dn) == normalize_dn(
            winner.application.som.dn
        ):
            return DormancyReason.SAME_SCOPE_MASKED, winner
        if candidate_app and winner.application.scope_index > candidate_app.scope_index:
            return DormancyReason.DESCENDANT_MASKED, winner
        return DormancyReason.OVERRIDDEN_SETTING, winner
