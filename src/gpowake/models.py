from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import Enum
from typing import Any, Iterable


class Capability(str, Enum):
    WRITE_GPLINK = "WriteGPLink"
    WRITE_GPOPTIONS = "WriteGPOptions"
    WRITE_GPO_CONTAINER = "WriteGPOContainer"
    WRITE_GPO_FILESYSTEM = "WriteGPOFileSystem"
    WRITE_GPO_SECURITY = "WriteGPOSecurity"
    # WRITE_DAC on a scope of management (owner-implicit or explicit); lets the
    # actor rewrite the SOM DACL to grant itself gPLink and then modify the link.
    WRITE_SOM_SECURITY = "WriteSOMSecurity"
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


class RegistryOperation(str, Enum):
    """One ordered MS-GPREG Registry.pol instruction."""

    SET_VALUE = "SET_VALUE"
    SET_IF_ABSENT = "SET_IF_ABSENT"
    DELETE_VALUE = "DELETE_VALUE"
    DELETE_ALL_VALUES = "DELETE_ALL_VALUES"
    DELETE_KEY = "DELETE_KEY"
    SECURE_KEY = "SECURE_KEY"


class ValueSensitivity(str, Enum):
    """How a setting value may be retained or rendered."""

    PUBLIC = "PUBLIC"
    SECRET = "SECRET"


class SomKind(str, Enum):
    SITE = "SITE"
    DOMAIN = "DOMAIN"
    OU = "OU"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AccessDecision(str, Enum):
    """A deterministic authorization result or an explicit coverage gap."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    UNKNOWN = "UNKNOWN"

    def __bool__(self) -> bool:
        raise TypeError(
            "AccessDecision has no truth value; compare it explicitly or use a can_* wrapper"
        )


class OutcomeClass(str, Enum):
    """How strongly a reported counterfactual is supported."""

    PROVEN = "PROVEN"
    POSSIBLE = "POSSIBLE"
    COVERAGE_GAP = "COVERAGE_GAP"


class Confidence(str, Enum):
    """Confidence in the modeled activation path, separate from impact."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class GptAccessSource(str, Enum):
    SMB_EFFECTIVE_IO = "SMB_EFFECTIVE_IO"
    WINDOWS_AUTHZ_ACCESSCHECK = "WINDOWS_AUTHZ_ACCESSCHECK"
    SMB_SHARE_NTFS_ACCESSCHECK = "SMB_SHARE_NTFS_ACCESSCHECK"


class AceType(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    # An ACE type GPOWake cannot interpret (callback/conditional/system ACEs).
    # It is retained in DACL order so the access check can fail closed instead
    # of silently dropping a potentially relevant deny.
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True)
class Ace:
    trustee_sid: str
    ace_type: AceType
    access_mask: int
    object_type: str | None = None
    inherited: bool = False
    # INHERIT_ONLY_ACE (0x08): the ACE applies only to child objects and does
    # not grant anything on the object that carries it.
    inherit_only: bool = False

    def __post_init__(self) -> None:
        if not 0 <= self.access_mask <= 0xFFFFFFFF:
            raise ValueError("ACE access_mask must fit in uint32")


@dataclass(frozen=True)
class AccessEvidence:
    """The owner condition or ACE that contributed to an access decision."""

    source: str
    detail: str
    ace_index: int | None = None
    trustee_sid: str | None = None
    access_mask: int | None = None
    object_type: str | None = None
    inherited: bool = False


@dataclass(frozen=True)
class AccessResult:
    decision: AccessDecision
    evidence: tuple[AccessEvidence, ...] = ()
    uncertainty_reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class SecurityDescriptor:
    aces: tuple[Ace, ...] = ()
    # A null DACL grants full access. An empty (but present) DACL grants none.
    null_dacl: bool = False
    collection_error: str | None = None
    # Owner SID: owners hold implicit READ_CONTROL/WRITE_DAC unless an explicit
    # OWNER RIGHTS (S-1-3-4) ACE constrains them.
    owner_sid: str | None = None
    # True when a UNSUPPORTED ACE is present; the access check fails closed.
    has_unsupported_ace: bool = False
    # AD's BlockOwnerImplicitRights behavior can suppress owner-implicit
    # WRITE_DAC on computer-derived objects. Collectors or fixtures set this
    # after evaluating the applicable dsHeuristics and requester token.
    owner_implicit_rights_blocked: bool = False
    # True only when the collector/fixture established that owner-implicit
    # rights semantics are known for this object. Live LDAP collection sets
    # this for the non-computer AD object classes GPOWake evaluates. An
    # unverified owner-derived grant is UNKNOWN rather than optimistic ALLOW.
    owner_implicit_rights_verified: bool = False


@dataclass(frozen=True)
class Link:
    gpo_dn: str
    options: int = 0
    order: int = 1

    def __post_init__(self) -> None:
        if not 0 <= self.options <= 0xFFFFFFFF:
            raise ValueError("gPLink options must fit in uint32")
        if self.order < 1:
            raise ValueError("gPLink order must be positive")

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

    def __post_init__(self) -> None:
        if not 0 <= self.gp_options <= 0xFFFFFFFF:
            raise ValueError("gPOptions must fit in uint32")

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
    # Automatic classifications carry a versioned rule identifier. A dangerous
    # snapshot setting with no rule ID remains an explicit user override.
    risk_rule_id: str | None = None
    unexpected_trustees: tuple[str, ...] = ()
    # SECRET values are destroyed at ingestion and may only be represented by
    # a presence marker. Serializers and renderers enforce this again.
    value_sensitivity: ValueSensitivity = ValueSensitivity.PUBLIC
    # Registry.pol is an ordered operation stream. These fields retain the
    # semantic target separately from the raw instruction spelling so delete,
    # set-if-absent, and key operations can be replayed correctly.
    registry_operation: RegistryOperation | None = None
    registry_key: str | None = None
    registry_value_name: str | None = None

    def __post_init__(self) -> None:
        registry_fields = (
            self.registry_operation,
            self.registry_key,
            self.registry_value_name,
        )
        if self.kind is not SettingKind.REGISTRY and any(
            item is not None for item in registry_fields
        ):
            raise ValueError("registry operation metadata requires a REGISTRY setting")
        if self.registry_operation is None:
            return
        if self.registry_key is None or not self.registry_key.strip():
            raise ValueError("registry operation requires a non-empty registry key")
        value_operations = {
            RegistryOperation.SET_VALUE,
            RegistryOperation.SET_IF_ABSENT,
            RegistryOperation.DELETE_VALUE,
        }
        if (
            self.registry_operation in value_operations
            and self.registry_value_name is None
        ):
            raise ValueError("registry value operation requires a value name")
        if (
            self.registry_operation not in value_operations
            and self.registry_value_name is not None
        ):
            raise ValueError("registry key operation cannot carry a value name")

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
    # Legacy/offline assertion that targets can read the GPT. Live collection
    # records collector access separately and requires per-target decisions.
    gpt_readable: bool = True
    collector_gpt_readable: bool | None = None
    settings_complete: bool = True
    settings_uncertainty_reasons: tuple[str, ...] = ()
    # The supported policy families whose files could not be collected or
    # parsed. An empty tuple while ``settings_complete`` is false is the
    # conservative legacy representation: any supported family may be absent.
    incomplete_setting_kinds: tuple[SettingKind, ...] = ()
    actor_gpt_write_decisions: tuple[tuple[str, AccessDecision], ...] = ()
    wmi_filter: str | None = None
    # True/False is an observed deterministic result. None means unknown/not evaluated.
    wmi_result: bool | None = None
    file_acl_writable_sids: tuple[str, ...] = ()
    version_number: int | None = None
    gpt_version: int | None = None
    usn_changed: int | None = None
    # Relative GPT path -> SHA-256, collected from the same SMB endpoint.
    gpt_hashes: tuple[tuple[str, str], ...] = ()
    # Relative GPT path -> byte length, collected from the same read as the hash.
    gpt_file_sizes: tuple[tuple[str, int], ...] = ()

    def __post_init__(self) -> None:
        if not 0 <= self.flags <= 0xFFFFFFFF:
            raise ValueError("GPO flags must fit in uint32")
        for name, value in (
            ("functionality_version", self.functionality_version),
            ("version_number", self.version_number),
            ("gpt_version", self.gpt_version),
            ("usn_changed", self.usn_changed),
        ):
            if value is not None and value < 0:
                raise ValueError(f"GPO {name} cannot be negative")
        if self.settings_complete and self.incomplete_setting_kinds:
            raise ValueError(
                "a settings-complete GPO cannot declare incomplete setting kinds"
            )
        hash_paths = [path.replace("/", "\\").casefold() for path, _ in self.gpt_hashes]
        size_paths = [
            path.replace("/", "\\").casefold() for path, _ in self.gpt_file_sizes
        ]
        if len(hash_paths) != len(set(hash_paths)):
            raise ValueError("GPO GPT hash paths must be unique")
        if len(size_paths) != len(set(size_paths)):
            raise ValueError("GPO GPT size paths must be unique")
        if any(type(size) is not int or size < 0 for _path, size in self.gpt_file_sizes):
            raise ValueError("GPO GPT file sizes must be non-negative integers")
        if size_paths and set(size_paths) != set(hash_paths):
            raise ValueError("GPO GPT hash and size paths must match exactly")
        for path, digest in self.gpt_hashes:
            canonical = path.replace("/", "\\")
            parts = canonical.split("\\")
            if canonical.startswith("\\") or ":" in canonical or any(
                part in {"", ".", ".."} for part in parts
            ):
                raise ValueError(f"GPO GPT path is unsafe: {path!r}")
            if len(digest) != 64:
                raise ValueError("GPO GPT SHA-256 must contain 64 hex digits")
            try:
                bytes.fromhex(digest)
            except ValueError as exc:
                raise ValueError("GPO GPT SHA-256 must be hexadecimal") from exc

    @property
    def computer_disabled(self) -> bool:
        return bool(self.flags & 0x2)

    def settings_incomplete_for(self, kind: SettingKind) -> bool:
        if self.settings_complete:
            return False
        return not self.incomplete_setting_kinds or kind in self.incomplete_setting_kinds

    def matches_identifier(self, identifier: str) -> bool:
        wanted = normalize_dn(identifier)
        identifiers = {
            normalize_dn(self.dn),
            normalize_dn(self.guid),
            normalize_dn(self.guid).strip("{}"),
        }
        return wanted in identifiers or wanted.strip("{}") in identifiers


@dataclass(frozen=True)
class Principal:
    sid: str
    name: str
    token_sids: tuple[str, ...]
    # True when the group token could not be fully enumerated (e.g. tokenGroups
    # was not readable); group-derived rights may be undercounted, so findings
    # for this principal must fail closed to LOW confidence.
    token_incomplete: bool = False

    @property
    def all_sids(self) -> frozenset[str]:
        return frozenset(normalize_sid(s) for s in (self.sid, *self.token_sids))


@dataclass(frozen=True)
class GptAccessProbe:
    """One machine-readable file probe made by a GPT access oracle."""

    relative_path: str
    status: str
    sha256: str | None = None
    size: int | None = None

    def __post_init__(self) -> None:
        if not self.relative_path.strip():
            raise ValueError("GPT access probe requires a relative path")
        if self.status not in {"READ_OK", "ACCESS_DENIED"}:
            raise ValueError("GPT access probe has an unsupported status")
        if self.status == "READ_OK" and self.sha256 is None:
            raise ValueError("a successful GPT access probe requires SHA-256")
        if self.status == "READ_OK" and (
            type(self.size) is not int or self.size < 0
        ):
            raise ValueError("a successful GPT access probe requires a byte size")
        if self.status == "ACCESS_DENIED" and self.sha256 is not None:
            raise ValueError("an access-denied GPT probe cannot carry file SHA-256")
        if self.status == "ACCESS_DENIED" and self.size is not None:
            raise ValueError("an access-denied GPT probe cannot carry a byte size")
        if self.sha256 is not None:
            if len(self.sha256) != 64:
                raise ValueError("GPT access probe SHA-256 must contain 64 hex digits")
            try:
                bytes.fromhex(self.sha256)
            except ValueError as exc:
                raise ValueError("GPT access probe SHA-256 must be hexadecimal") from exc


@dataclass(frozen=True)
class GptAccessObservation:
    """Target-specific GPT authorization supplied by a supported oracle."""

    gpo_id: str
    decision: AccessDecision
    source: GptAccessSource
    oracle: str
    oracle_version: str
    snapshot_sha256: str
    observed_at: str
    desired_access: int
    gpt_unc_path: str
    dc: str
    target_sid: str
    token_sids_sha256: str
    credential_principal: str
    authenticated_sid: str
    identity_attestation: str
    gpo_ad_version: int
    gpt_version: int
    share_sd_sha256: str | None
    ntfs_sd_sha256: str | None
    probes: tuple[GptAccessProbe, ...]

    def __post_init__(self) -> None:
        if not self.gpo_id.strip():
            raise ValueError("GPT access observation requires a GPO identifier")
        if not isinstance(self.source, GptAccessSource):
            raise ValueError("GPT access observation has an unsupported source")
        if not self.oracle.strip():
            raise ValueError("GPT access observation requires an oracle identity")
        if not self.oracle_version.strip():
            raise ValueError("GPT access observation requires an oracle version")
        if len(self.snapshot_sha256) != 64:
            raise ValueError("GPT observation snapshot SHA-256 must contain 64 hex digits")
        try:
            bytes.fromhex(self.snapshot_sha256)
        except ValueError as exc:
            raise ValueError("GPT observation snapshot SHA-256 must be hexadecimal") from exc
        if not self.observed_at.strip():
            raise ValueError("GPT access observation requires an observation time")
        try:
            observed = datetime.fromisoformat(
                self.observed_at.replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ValueError(
                "GPT access observation time must be an ISO-8601 timestamp"
            ) from exc
        if observed.tzinfo is None:
            raise ValueError("GPT access observation time must include a UTC offset")
        if not 0 <= self.desired_access <= 0xFFFFFFFF:
            raise ValueError("GPT desired access must fit in uint32")
        for field_name, value in (
            ("GPT UNC path", self.gpt_unc_path),
            ("DC", self.dc),
            ("target SID", self.target_sid),
            ("credential principal", self.credential_principal),
            ("authenticated SID", self.authenticated_sid),
            ("identity attestation", self.identity_attestation),
        ):
            if not value.strip():
                raise ValueError(f"GPT access observation requires {field_name}")
        if len(self.token_sids_sha256) != 64:
            raise ValueError("target token SID hash must contain 64 hex digits")
        try:
            bytes.fromhex(self.token_sids_sha256)
        except ValueError as exc:
            raise ValueError("target token SID hash must be hexadecimal") from exc
        if self.gpo_ad_version < 0 or self.gpt_version < 0:
            raise ValueError("observed GPO versions cannot be negative")
        for field_name, digest in (
            ("share security descriptor", self.share_sd_sha256),
            ("NTFS security descriptor", self.ntfs_sd_sha256),
        ):
            if digest is None:
                continue
            if len(digest) != 64:
                raise ValueError(f"{field_name} hash must contain 64 hex digits")
            try:
                bytes.fromhex(digest)
            except ValueError as exc:
                raise ValueError(f"{field_name} hash must be hexadecimal") from exc
        if not self.probes:
            raise ValueError("GPT access observation requires at least one file probe")
        if normalize_sid(self.authenticated_sid) != normalize_sid(self.target_sid):
            raise ValueError("authenticated SID must equal the bound snapshot target SID")
        if self.decision is not self.decision_for():
            raise ValueError("GPT aggregate decision does not match its file probes")

    def decision_for(self, kind: SettingKind | None = None) -> AccessDecision:
        """Return the global or supported setting-family result for this evidence."""

        by_path = {probe.relative_path.replace("/", "\\").casefold(): probe for probe in self.probes}
        root = by_path.get("gpt.ini")
        if root is None:
            return AccessDecision.UNKNOWN
        if root.status == "ACCESS_DENIED":
            return AccessDecision.DENY
        if kind is None:
            statuses = {probe.status for probe in self.probes}
            if statuses == {"READ_OK"}:
                return AccessDecision.ALLOW
            if "ACCESS_DENIED" in statuses:
                return AccessDecision.UNKNOWN
            return AccessDecision.UNKNOWN
        family_paths = [
            probe
            for path, probe in by_path.items()
            if kind in setting_kinds_for_gpt_path(path)
        ]
        if not family_paths:
            return AccessDecision.UNKNOWN
        if any(probe.status == "ACCESS_DENIED" for probe in family_paths):
            return AccessDecision.DENY
        return AccessDecision.ALLOW


@dataclass(frozen=True)
class Target:
    dn: str
    name: str
    sid: str
    som_dn: str
    token_sids: tuple[str, ...]
    sam_account_name: str | None = None
    dns_domain: str | None = None
    netbios_domain: str | None = None
    site_dn: str | None = None
    criticality: str = "NORMAL"
    # Legacy all-or-nothing marker retained for schema-1 compatibility. New
    # collection records the exact unresolved ACL trustees below instead.
    token_incomplete: bool = False
    unresolved_token_sids: tuple[str, ...] = ()
    # WMI results are target observations keyed by the GPO's WMI filter ID/DN.
    wmi_results: tuple[tuple[str, bool], ...] = ()
    # Structured observations take precedence over the schema-2 legacy tuple.
    gpt_read_observations: tuple[GptAccessObservation, ...] = ()
    gpt_read_decisions: tuple[tuple[str, AccessDecision], ...] = ()
    site_resolution_error: str | None = None

    @property
    def all_sids(self) -> frozenset[str]:
        return frozenset(normalize_sid(s) for s in (self.sid, *self.token_sids))

    @property
    def unresolved_sids(self) -> frozenset[str]:
        return frozenset(normalize_sid(s) for s in self.unresolved_token_sids)

    def wmi_result_for(self, wmi_filter: str) -> bool | None:
        wanted = normalize_dn(wmi_filter)
        for filter_id, result in self.wmi_results:
            if normalize_dn(filter_id) == wanted:
                return bool(result)
        return None

    def gpt_read_decision_for(
        self, gpo: GPO, setting_kind: SettingKind | None = None
    ) -> AccessDecision | None:
        for observation in self.gpt_read_observations:
            if gpo.matches_identifier(observation.gpo_id):
                return observation.decision_for(setting_kind)
        for gpo_id, decision in self.gpt_read_decisions:
            if gpo.matches_identifier(gpo_id):
                return AccessDecision(decision)
        return None

    def gpt_root_read_decision_for(self, gpo: GPO) -> AccessDecision | None:
        """Return only the gpt.ini gate, independent of policy-file families."""

        for observation in self.gpt_read_observations:
            if not gpo.matches_identifier(observation.gpo_id):
                continue
            root = next(
                (
                    probe
                    for probe in observation.probes
                    if probe.relative_path.replace("/", "\\").casefold() == "gpt.ini"
                ),
                None,
            )
            if root is None:
                return AccessDecision.UNKNOWN
            return (
                AccessDecision.ALLOW
                if root.status == "READ_OK"
                else AccessDecision.DENY
            )
        for gpo_id, decision in self.gpt_read_decisions:
            if gpo.matches_identifier(gpo_id):
                return AccessDecision(decision)
        return None


@dataclass(frozen=True)
class GptAccessProvenance:
    target: str
    target_sid: str
    authenticated_sid: str
    credential_principal: str
    identity_attestation: str
    decision: AccessDecision
    source: GptAccessSource
    oracle: str
    oracle_version: str
    observed_at: str
    snapshot_sha256: str
    dc: str
    token_sids_sha256: str


@dataclass
class Environment:
    soms: dict[str, ScopeOfManagement]
    gpos: dict[str, GPO]
    principals: list[Principal]
    targets: list[Target]
    source_dc: str | None = None
    warnings: list[str] = field(default_factory=list)
    domain_sid: str | None = None
    forest_root_sid: str | None = None
    ldap_endpoint: str | None = None
    smb_endpoint: str | None = None
    tls_verified: bool | None = None
    collected_at: str | None = None

    def __post_init__(self) -> None:
        soms = {normalize_dn(value.dn): value for value in self.soms.values()}
        gpos = {normalize_dn(value.dn): value for value in self.gpos.values()}
        if len(soms) != len(self.soms):
            raise ValueError("SOM DNs must be unique")
        if len(gpos) != len(self.gpos):
            raise ValueError("GPO DNs must be unique")
        guids = [normalize_dn(value.guid).strip("{}") for value in gpos.values()]
        if len(guids) != len(set(guids)):
            raise ValueError("GPO GUIDs must be unique")
        self.soms = soms
        self.gpos = gpos

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
    # Use WRITE_DAC on a SOM to grant the actor WriteGPLink, enabling a
    # subsequent link modification. The two form one two-action path.
    GRANT_GPLINK = "GrantWriteGPLink"
    REWRITE_GPLINK_DACL = "ExplicitBlockerRewriteWriteGPLink"
    REWRITE_READ_APPLY_DACL = "ExplicitBlockerRewriteReadAndApplyGroupPolicy"


class DaclRewriteMode(str, Enum):
    ADDITIVE_GRANT = "ADDITIVE_GRANT"
    EXPLICIT_BLOCKER_REWRITE = "EXPLICIT_BLOCKER_REWRITE"


@dataclass(frozen=True)
class Action:
    type: ActionType
    capability: Capability
    description: str
    gpo_dn: str | None = None
    som_dn: str | None = None
    link_order: int | None = None
    target_sid: str | None = None
    target_sids: tuple[str, ...] = ()
    authorization: tuple[AccessEvidence, ...] = ()
    dacl_removed: tuple[Ace, ...] = ()
    dacl_added: tuple[Ace, ...] = ()
    # Human- and machine-readable upper bound on rights newly exposed by a
    # conservative additive DACL rewrite.
    newly_exposed_rights: tuple[str, ...] = ()
    dacl_rewrite_mode: DaclRewriteMode | None = None
    # Trustees named by a removed ACE can have members outside the snapshot.
    collateral_trustees: tuple[str, ...] = ()
    # Before/after authorization changes for observed principals or targets,
    # plus an explicit warning for membership outside the snapshot.
    collateral_effects: tuple[str, ...] = ()

    def identity(self) -> tuple[Any, ...]:
        return (
            self.type.value,
            normalize_dn(self.gpo_dn or ""),
            normalize_dn(self.som_dn or ""),
            self.link_order,
            normalize_sid(self.target_sid or ""),
            self.dacl_rewrite_mode.value if self.dacl_rewrite_mode else "",
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
    # The representative (fewest-action, then lexicographic) activation path.
    actions: tuple[Action, ...]
    targets: list[str]
    target_dns: list[str]
    result_value: Any
    severity: Severity
    score: float
    requires_gpo_edit: bool
    requires_sysvol_write: bool = False
    # Other minimal activation paths for the same dormant setting (e.g. reorder
    # vs. enforce). Reported as alternatives on a single finding rather than as
    # separate duplicate-looking findings.
    alternative_paths: tuple[tuple[Action, ...], ...] = ()
    outcome: OutcomeClass = OutcomeClass.POSSIBLE
    confidence: Confidence = Confidence.LOW
    confidence_reasons: tuple[str, ...] = ()
    uncertainty_reasons: tuple[str, ...] = ()
    rule_id: str | None = None
    value_sensitivity: ValueSensitivity = ValueSensitivity.PUBLIC
    current_value_sensitivity: ValueSensitivity = ValueSensitivity.PUBLIC
    current_value: Any = None
    newly_privileged_trustees: tuple[str, ...] = ()
    target_role: str = "NORMAL"
    current_processing_trace: tuple[str, ...] = ()
    counterfactual_trace: tuple[str, ...] = ()
    ad_version: int | None = None
    gpt_version: int | None = None
    usn_changed: int | None = None
    gpt_hashes: tuple[tuple[str, str], ...] = ()
    sysvol_readable: bool = True
    collector_sysvol_readable: bool | None = None
    gpt_access_provenance: tuple[GptAccessProvenance, ...] = ()

    @property
    def paths(self) -> tuple[tuple[Action, ...], ...]:
        """Every minimal activation path: the representative one, then the rest."""
        return (tuple(self.actions), *self.alternative_paths)


@dataclass(frozen=True)
class CoverageGap:
    """A gate that prevented a deterministic counterfactual conclusion."""

    gap_id: str
    principal: str
    principal_sid: str
    gpo_name: str
    gpo_dn: str
    target: str
    target_dn: str
    gate: str
    reason: str


def normalize_dn(value: str) -> str:
    return value.strip().casefold()


def normalize_sid(value: str) -> str:
    return value.strip().upper()


def unique_normalized_sids(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(normalize_sid(v) for v in values if v))


def setting_kinds_for_gpt_path(relative_path: str) -> tuple[SettingKind, ...]:
    """Map the supported GPT files to the setting families they control."""

    path = relative_path.replace("/", "\\").casefold()
    if path == "machine\\microsoft\\windows nt\\secedit\\gpttmpl.inf":
        return (
            SettingKind.PRIVILEGE_RIGHT,
            SettingKind.RESTRICTED_GROUP,
            SettingKind.SECURITY_OPTION,
        )
    if path == "machine\\registry.pol":
        return (SettingKind.REGISTRY,)
    return ()
