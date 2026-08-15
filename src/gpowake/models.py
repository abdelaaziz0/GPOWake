from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Iterable


class Capability(str, Enum):
    WRITE_GPLINK = "WriteGPLink"
    WRITE_GPOPTIONS = "WriteGPOptions"
    WRITE_GPO_CONTAINER = "WriteGPOContainer"
    WRITE_GPO_FILESYSTEM = "WriteGPOFileSystem"
    WRITE_GPO_SECURITY = "WriteGPOSecurity"
    WRITE_WMI_FILTER = "WriteWMIFilter"


class DormancyReason(str, Enum):
    UNLINKED = "UNLINKED"
    LINK_DISABLED = "LINK_DISABLED"
    SAME_SCOPE_MASKED = "SAME_SCOPE_MASKED"
    DESCENDANT_MASKED = "DESCENDANT_MASKED"
    BLOCKED_INHERITANCE = "BLOCKED_INHERITANCE"
    SECURITY_FILTERED = "SECURITY_FILTERED"
    WMI_FILTERED = "WMI_FILTERED"
    SECTION_DISABLED = "SECTION_DISABLED"
    EXTENSION_MISSING = "EXTENSION_MISSING"
    GPT_UNREADABLE = "GPT_UNREADABLE"
    OVERRIDDEN_SETTING = "OVERRIDDEN_SETTING"


class SettingKind(str, Enum):
    PRIVILEGE_RIGHT = "PRIVILEGE_RIGHT"
    RESTRICTED_GROUP = "RESTRICTED_GROUP"
    SECURITY_OPTION = "SECURITY_OPTION"
    REGISTRY = "REGISTRY"


class SomKind(str, Enum):
    SITE = "SITE"
    DOMAIN = "DOMAIN"
    OU = "OU"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AceType(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


@dataclass(frozen=True)
class Ace:
    trustee_sid: str
    ace_type: AceType
    access_mask: int
    object_type: str | None = None
    inherited: bool = False


@dataclass(frozen=True)
class SecurityDescriptor:
    aces: tuple[Ace, ...] = ()
    # A null DACL grants full access. An empty (but present) DACL grants none.
    null_dacl: bool = False
    collection_error: str | None = None


@dataclass(frozen=True)
class Link:
    gpo_dn: str
    options: int = 0
    order: int = 1

    @property
    def disabled(self) -> bool:
        return bool(self.options & 0x1)

    @property
    def enforced(self) -> bool:
        return bool(self.options & 0x2)

    def with_disabled(self, disabled: bool) -> "Link":
        options = self.options | 0x1 if disabled else self.options & ~0x1
        return replace(self, options=options)

    def with_enforced(self, enforced: bool) -> "Link":
        options = self.options | 0x2 if enforced else self.options & ~0x2
        return replace(self, options=options)


@dataclass(frozen=True)
class ScopeOfManagement:
    dn: str
    kind: SomKind
    parent_dn: str | None = None
    links: tuple[Link, ...] = ()
    gp_options: int = 0
    security_descriptor: SecurityDescriptor = field(default_factory=SecurityDescriptor)

    @property
    def blocks_inheritance(self) -> bool:
        return bool(self.gp_options & 0x1)


@dataclass(frozen=True)
class Setting:
    kind: SettingKind
    name: str
    value: Any
    dangerous: bool = False
    severity: Severity = Severity.MEDIUM
    rationale: str = ""
    required_extension: str | None = None

    @property
    def key(self) -> tuple[str, str]:
        return self.kind.value, self.name.casefold()


@dataclass(frozen=True)
class GPO:
    dn: str
    guid: str
    name: str
    flags: int = 0
    functionality_version: int | None = None
    file_sys_path: str | None = None
    machine_extensions: tuple[str, ...] | None = None
    settings: tuple[Setting, ...] = ()
    security_descriptor: SecurityDescriptor = field(default_factory=SecurityDescriptor)
    gpt_readable: bool = True
    wmi_filter: str | None = None
    # True/False is an observed deterministic result. None means unknown/not evaluated.
    wmi_result: bool | None = None
    file_acl_writable_sids: tuple[str, ...] = ()
    version_number: int | None = None
    gpt_version: int | None = None

    @property
    def computer_disabled(self) -> bool:
        return bool(self.flags & 0x2)


@dataclass(frozen=True)
class Principal:
    sid: str
    name: str
    token_sids: tuple[str, ...]

    @property
    def all_sids(self) -> frozenset[str]:
        return frozenset(normalize_sid(s) for s in (self.sid, *self.token_sids))


@dataclass(frozen=True)
class Target:
    dn: str
    name: str
    sid: str
    som_dn: str
    token_sids: tuple[str, ...]
    site_dn: str | None = None
    criticality: str = "NORMAL"

    @property
    def all_sids(self) -> frozenset[str]:
        return frozenset(normalize_sid(s) for s in (self.sid, *self.token_sids))


@dataclass
class Environment:
    soms: dict[str, ScopeOfManagement]
    gpos: dict[str, GPO]
    principals: list[Principal]
    targets: list[Target]
    source_dc: str | None = None
    warnings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.soms = {normalize_dn(k): v for k, v in self.soms.items()}
        self.gpos = {normalize_dn(k): v for k, v in self.gpos.items()}

    def som(self, dn: str) -> ScopeOfManagement | None:
        return self.soms.get(normalize_dn(dn))

    def gpo(self, dn: str) -> GPO | None:
        return self.gpos.get(normalize_dn(dn))


class ActionType(str, Enum):
    ADD_LINK = "AddLink"
    ENABLE_LINK = "EnableLink"
    REORDER_LINK = "ReorderLink"
    SET_ENFORCED = "SetEnforced"
    CLEAR_BLOCK_INHERITANCE = "ClearBlockInheritance"
    GRANT_READ_APPLY = "GrantReadAndApplyGroupPolicy"
    ENABLE_COMPUTER_SECTION = "EnableComputerSection"


@dataclass(frozen=True)
class Action:
    type: ActionType
    capability: Capability
    description: str
    gpo_dn: str | None = None
    som_dn: str | None = None
    link_order: int | None = None
    target_sid: str | None = None

    def identity(self) -> tuple[Any, ...]:
        return (
            self.type.value,
            normalize_dn(self.gpo_dn or ""),
            normalize_dn(self.som_dn or ""),
            self.link_order,
            normalize_sid(self.target_sid or ""),
        )


@dataclass
class Finding:
    finding_id: str
    principal: str
    principal_sid: str
    capability: Capability
    capabilities: tuple[Capability, ...]
    gpo_name: str
    gpo_dn: str
    setting_kind: SettingKind
    setting_name: str
    dormant_value: Any
    reason: DormancyReason
    current_winner: str | None
    actions: tuple[Action, ...]
    targets: list[str]
    target_dns: list[str]
    result_value: Any
    severity: Severity
    score: float
    confidence: str
    requires_gpo_edit: bool
    requires_sysvol_write: bool = False


def normalize_dn(value: str) -> str:
    return value.strip().casefold()


def normalize_sid(value: str) -> str:
    return value.strip().upper()


def unique_normalized_sids(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(normalize_sid(v) for v in values if v))
