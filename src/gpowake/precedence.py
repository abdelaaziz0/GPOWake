from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum

from .acl import evaluate_apply_gpo, evaluate_read_gpo
from .models import (
    AccessDecision,
    DormancyReason,
    Environment,
    GPO,
    Link,
    RegistryOperation,
    ScopeOfManagement,
    Setting,
    SettingKind,
    SomKind,
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
class PolicyUncertainty:
    """An unknown policy input, scoped to what it can actually affect."""

    reason: str
    gate: str
    gpo_dn: str | None = None
    som_dn: str | None = None
    link_order: int | None = None
    setting_keys: tuple[tuple[str, str], ...] = ()
    setting_kinds: tuple[SettingKind, ...] = ()

    def affects(self, setting: Setting) -> bool:
        if self.setting_keys and setting.key in self.setting_keys:
            return True
        if self.setting_kinds and setting.kind in self.setting_kinds:
            return True
        return not self.setting_keys and not self.setting_kinds


@dataclass(frozen=True)
class Evaluation:
    target: Target
    chain: tuple[ScopeOfManagement, ...]
    links: tuple[LinkEvaluation, ...]
    processing_order: tuple[LinkEvaluation, ...]
    winners: dict[tuple[str, str], EffectiveSetting]
    # Restricted Groups "Member Of" is inclusion-only. Retain each effective
    # contributor as well as the merged value so the solver can prove that a
    # specific dormant GPO became effective without pretending there is one
    # last-writer winner.
    additive_contributors: dict[
        tuple[str, str], tuple[EffectiveSetting, ...]
    ]
    uncertainties: tuple[PolicyUncertainty, ...] = ()

    @property
    def uncertainty_reasons(self) -> tuple[str, ...]:
        """All reasons for display/backward compatibility, never as a solver gate."""

        return tuple(dict.fromkeys(item.reason for item in self.uncertainties))

    def uncertainties_for(self, setting: Setting) -> tuple[PolicyUncertainty, ...]:
        return tuple(item for item in self.uncertainties if item.affects(setting))

    def uncertainty_reasons_for(self, setting: Setting) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(item.reason for item in self.uncertainties_for(setting))
        )


class PolicyEngine:
    """Evaluate deterministic computer-side policy ordering for one target."""

    def __init__(self, environment: Environment):
        self.environment = environment

    def _site_resolution_uncertainty(
        self, target: Target
    ) -> PolicyUncertainty | None:
        """Scope an unknown site only to policy that a site could contribute."""

        if not target.site_resolution_error:
            return None
        setting_keys: set[tuple[str, str]] = set()
        setting_kinds: set[SettingKind] = set()
        unscoped = False
        for som in self.environment.soms.values():
            if som.kind is not SomKind.SITE:
                continue
            for link in som.links:
                if link.disabled:
                    continue
                gpo = self.environment.gpo(link.gpo_dn)
                if gpo is None:
                    unscoped = True
                    continue
                setting_keys.update(setting.key for setting in gpo.settings)
                if not gpo.settings_complete:
                    if gpo.incomplete_setting_kinds:
                        setting_kinds.update(gpo.incomplete_setting_kinds)
                    else:
                        unscoped = True
        if unscoped:
            return PolicyUncertainty(target.site_resolution_error, "SITE_RESOLUTION")
        if not setting_keys and not setting_kinds:
            return None
        return PolicyUncertainty(
            target.site_resolution_error,
            "SITE_RESOLUTION",
            setting_keys=tuple(sorted(setting_keys)),
            setting_kinds=tuple(sorted(setting_kinds, key=lambda item: item.value)),
        )

    def som_chain(self, target: Target) -> tuple[ScopeOfManagement, ...]:
        chain: list[ScopeOfManagement] = []
        seen: set[str] = set()
        current = self.environment.som(target.som_dn)
        if current is None:
            raise ValueError(
                f"target {target.dn} refers to missing SOM {target.som_dn}"
            )
        while current is not None:
            key = normalize_dn(current.dn)
            if key in seen:
                raise ValueError(f"cycle in SOM hierarchy at {current.dn}")
            seen.add(key)
            chain.append(current)
            if current.parent_dn:
                parent = self.environment.som(current.parent_dn)
                if parent is None:
                    raise ValueError(
                        f"SOM {current.dn} refers to missing parent {current.parent_dn}"
                    )
                current = parent
            else:
                current = None
        chain.reverse()
        if target.site_dn:
            site = self.environment.som(target.site_dn)
            if site is None:
                raise ValueError(
                    f"target {target.dn} refers to missing site {target.site_dn}"
                )
            if normalize_dn(site.dn) not in seen:
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
            return LinkEvaluation(
                som,
                link,
                scope_index,
                LinkStatus.GPO_MISSING,
                uncertain=True,
                detail="linked GPO was not collected",
            )
        if (
            gpo.functionality_version is None
            and self.environment.collected_at is not None
        ):
            return LinkEvaluation(
                som,
                link,
                scope_index,
                LinkStatus.UNSUPPORTED,
                uncertain=True,
                detail="gPCFunctionalityVersion was not returned during collection",
            )
        if gpo.functionality_version is not None and gpo.functionality_version != 2:
            return LinkEvaluation(
                som,
                link,
                scope_index,
                LinkStatus.UNSUPPORTED,
                detail=f"unsupported gPCFunctionalityVersion {gpo.functionality_version}",
            )
        target_gpt_read = target.gpt_root_read_decision_for(gpo)
        if target_gpt_read is AccessDecision.DENY:
            return LinkEvaluation(som, link, scope_index, LinkStatus.GPT_UNREADABLE)
        if target_gpt_read is AccessDecision.UNKNOWN:
            return LinkEvaluation(
                som,
                link,
                scope_index,
                LinkStatus.GPT_UNREADABLE,
                uncertain=True,
                detail="target GPT read authorization is unknown",
            )
        if target_gpt_read is None:
            if self.environment.collected_at is not None:
                return LinkEvaluation(
                    som,
                    link,
                    scope_index,
                    LinkStatus.GPT_UNREADABLE,
                    uncertain=True,
                    detail=(
                        "collector GPT readability is not target GPT read "
                        "authorization"
                    ),
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
        if target.token_incomplete and not target.unresolved_token_sids:
            return LinkEvaluation(
                som,
                link,
                scope_index,
                LinkStatus.SECURITY_FILTERED,
                uncertain=True,
                detail=(
                    "legacy snapshot marks the entire target token incomplete; "
                    "trustee-scoped uncertainty is unavailable"
                ),
            )
        read_result = evaluate_read_gpo(
            gpo.security_descriptor,
            target.all_sids,
            unresolved_token_sids=target.unresolved_sids,
        )
        apply_result = evaluate_apply_gpo(
            gpo.security_descriptor,
            target.all_sids,
            unresolved_token_sids=target.unresolved_sids,
        )
        if AccessDecision.UNKNOWN in {read_result.decision, apply_result.decision}:
            return LinkEvaluation(
                som,
                link,
                scope_index,
                LinkStatus.SECURITY_FILTERED,
                uncertain=True,
                detail=(
                    "security-filter authorization is unknown "
                    f"(read={read_result.decision.value}, "
                    f"apply={apply_result.decision.value})"
                ),
            )
        if (
            read_result.decision is not AccessDecision.ALLOW
            or apply_result.decision is not AccessDecision.ALLOW
        ):
            return LinkEvaluation(som, link, scope_index, LinkStatus.SECURITY_FILTERED)
        if gpo.wmi_filter:
            target_wmi_result = target.wmi_result_for(gpo.wmi_filter)
            if target_wmi_result is False or gpo.wmi_result is False:
                return LinkEvaluation(som, link, scope_index, LinkStatus.WMI_FILTERED)
            if target_wmi_result is None:
                return LinkEvaluation(
                    som,
                    link,
                    scope_index,
                    LinkStatus.WMI_FILTERED,
                    uncertain=True,
                    detail=(
                        "WMI filter result was not evaluated for this target; "
                        "a legacy global true result is not accepted"
                    ),
                )
        return LinkEvaluation(
            som, link, scope_index, LinkStatus.APPLIES, uncertain, detail
        )

    @staticmethod
    def is_restricted_member_of(setting: Setting) -> bool:
        if setting.kind is not SettingKind.RESTRICTED_GROUP:
            return False
        _group, separator, relationship = setting.name.partition("/")
        return bool(separator) and relationship.casefold() == "memberof"

    @staticmethod
    def _processing_key(item: LinkEvaluation) -> tuple[int, int, int]:
        # Normal links: site/domain/OU from broad to specific, and high numeric
        # link order first so order 1 is processed last. Enforced links are then
        # processed from the deepest scope toward the root; root enforcement wins.
        if item.link.enforced:
            return 1, -item.scope_index, -item.link.order
        return 0, item.scope_index, -item.link.order

    @staticmethod
    def _registry_key(setting: Setting) -> str:
        key = setting.registry_key
        if key is None:
            key = setting.name.rsplit("\\", 1)[0] if "\\" in setting.name else ""
        return key.replace("/", "\\").rstrip("\\").casefold()

    @classmethod
    def _apply_registry_operation(
        cls,
        winners: dict[tuple[str, str], EffectiveSetting],
        setting: Setting,
        effective: EffectiveSetting,
    ) -> None:
        operation = setting.registry_operation or RegistryOperation.SET_VALUE
        if operation is RegistryOperation.SET_VALUE:
            winners[setting.key] = effective
            return
        if operation is RegistryOperation.SET_IF_ABSENT:
            winners.setdefault(setting.key, effective)
            return
        if operation is RegistryOperation.DELETE_VALUE:
            winners.pop(setting.key, None)
            return
        if operation is RegistryOperation.SECURE_KEY:
            # **SecureKey changes the registry key ACL, not effective value data.
            return

        target_key = cls._registry_key(setting)
        for winner_key, current in tuple(winners.items()):
            if current.setting.kind is not SettingKind.REGISTRY:
                continue
            current_key = cls._registry_key(current.setting)
            if operation is RegistryOperation.DELETE_ALL_VALUES:
                remove = current_key == target_key
            else:
                remove = current_key == target_key or current_key.startswith(
                    target_key + "\\"
                )
            if remove:
                winners.pop(winner_key, None)

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
        additive_contributors: dict[
            tuple[str, str], list[EffectiveSetting]
        ] = {}
        uncertainties: list[PolicyUncertainty] = []
        site_uncertainty = self._site_resolution_uncertainty(target)
        if site_uncertainty is not None:
            uncertainties.append(site_uncertainty)
        for item in links:
            if not item.uncertain or not item.detail:
                continue
            gpo = self.environment.gpo(item.link.gpo_dn)
            if gpo is None:
                uncertainties.append(
                    PolicyUncertainty(
                        f"{item.som.dn} link order {item.link.order}: {item.detail}",
                        "GPO_COLLECTION",
                        som_dn=item.som.dn,
                        link_order=item.link.order,
                    )
                )
                continue
            incomplete_kinds = (
                gpo.incomplete_setting_kinds
                if not gpo.settings_complete
                else ()
            )
            legacy_unscoped = not gpo.settings_complete and not incomplete_kinds
            uncertainties.append(
                PolicyUncertainty(
                    f"{item.som.dn} link order {item.link.order}: {item.detail}",
                    {
                        LinkStatus.SECURITY_FILTERED: "SECURITY_FILTER",
                        LinkStatus.GPT_UNREADABLE: "TARGET_GPT_READ",
                        LinkStatus.WMI_FILTERED: "WMI_FILTER",
                        LinkStatus.UNSUPPORTED: "GPO_METADATA",
                    }.get(item.status, "POLICY_GATE"),
                    gpo_dn=gpo.dn,
                    som_dn=item.som.dn,
                    link_order=item.link.order,
                    setting_keys=(
                        ()
                        if legacy_unscoped
                        else tuple(setting.key for setting in gpo.settings)
                    ),
                    setting_kinds=incomplete_kinds,
                )
            )
        for application in processing:
            gpo = self.environment.gpo(application.link.gpo_dn)
            if gpo is None:
                continue
            if not gpo.settings_complete:
                reasons = gpo.settings_uncertainty_reasons or (
                    "one or more supported GPT policy files were not collected",
                )
                for reason in reasons:
                    uncertainties.append(
                        PolicyUncertainty(
                            f"{gpo.name}: {reason}",
                            "GPT_SETTINGS",
                            gpo_dn=gpo.dn,
                            setting_kinds=gpo.incomplete_setting_kinds,
                        )
                    )
            for setting in gpo.settings:
                target_gpt_read = target.gpt_read_decision_for(gpo, setting.kind)
                if target_gpt_read is AccessDecision.DENY:
                    continue
                if target_gpt_read is AccessDecision.UNKNOWN or (
                    target_gpt_read is None
                    and self.environment.collected_at is not None
                ):
                    uncertainties.append(
                        PolicyUncertainty(
                            f"{gpo.name}: target access to the GPT file family for "
                            f"{setting.kind.value} was not established",
                            "TARGET_GPT_READ",
                            gpo_dn=gpo.dn,
                            setting_keys=(setting.key,),
                            setting_kinds=(setting.kind,),
                        )
                    )
                    continue
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
                    uncertainties.append(
                        PolicyUncertainty(
                            f"{gpo.name}: machine CSE advertisement is unknown for "
                            f"{setting.name}",
                            "CSE_ADVERTISEMENT",
                            gpo_dn=gpo.dn,
                            setting_keys=(setting.key,),
                        )
                    )
                effective = EffectiveSetting(
                    setting=setting,
                    gpo=gpo,
                    application=application,
                    uncertain=application.uncertain or extension_uncertain,
                )
                if setting.kind is SettingKind.REGISTRY:
                    self._apply_registry_operation(winners, setting, effective)
                elif self.is_restricted_member_of(setting):
                    contributors = additive_contributors.setdefault(setting.key, [])
                    contributors.append(effective)
                    current = winners.get(setting.key)
                    if current is None:
                        winners[setting.key] = effective
                    else:
                        current_values = (
                            current.setting.value
                            if isinstance(current.setting.value, (list, tuple, set))
                            else ()
                        )
                        new_values = (
                            setting.value
                            if isinstance(setting.value, (list, tuple, set))
                            else ()
                        )
                        merged = tuple(dict.fromkeys((*current_values, *new_values)))
                        winners[setting.key] = replace(
                            effective,
                            setting=replace(setting, value=merged),
                            uncertain=current.uncertain or effective.uncertain,
                        )
                else:
                    winners[setting.key] = effective
        return Evaluation(
            target,
            chain,
            links,
            processing,
            winners,
            {
                key: tuple(contributors)
                for key, contributors in additive_contributors.items()
            },
            tuple(dict.fromkeys(uncertainties)),
        )

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
        target_gpt_read = evaluation.target.gpt_read_decision_for(
            candidate, setting.kind
        )
        if target_gpt_read is AccessDecision.DENY:
            return DormancyReason.GPT_UNREADABLE, evaluation.winners.get(setting.key)
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
