from __future__ import annotations

import re
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlparse

from ..acl import (
    ADS_RIGHT_DS_CONTROL_ACCESS,
    DIRECTORY_GENERIC_READ,
    GENERIC_ALL,
    GENERIC_READ,
    parse_security_descriptor,
)
from ..gplink import parse_gplink
from ..models import (
    AceType,
    Environment,
    GPO,
    Principal,
    ScopeOfManagement,
    SomKind,
    SettingKind,
    Target,
    normalize_dn,
    unique_normalized_sids,
    normalize_sid,
)


EVERYONE = "S-1-1-0"
AUTHENTICATED_USERS = "S-1-5-11"
EMPTY_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"
_GUID_RE = re.compile(r"\{([0-9a-fA-F-]{36})\}")

# Security descriptor control flags: OWNER (0x01) | DACL (0x04). The owner is
# required to evaluate implicit owner rights (READ_CONTROL/WRITE_DAC).
_SD_FLAGS_OWNER_DACL = 0x05


@dataclass(frozen=True)
class AuthConfig:
    username: str = ""
    password: str = ""
    auth_domain: str = ""
    lmhash: str = ""
    nthash: str = ""
    kerberos: bool = False
    ccache: str | None = None
    # Explicit opt-in required before a credentialed SIMPLE bind runs over a
    # non-TLS (ldap://) connection, which would send the password in the clear.
    allow_insecure_simple_bind: bool = False


@dataclass(frozen=True)
class CollectionConfig:
    domain: str
    dc_ip: str
    dc_host: str | None = None
    ldap_uri: str | None = None
    principals: tuple[str, ...] = ()
    target_filter: str = "(objectCategory=computer)"
    # Optional target selection (name/DN/SID). Applied before the per-target
    # tokenGroups round trip so filtered-out computers are never queried.
    target_names: tuple[str, ...] = ()
    auth: AuthConfig = AuthConfig()
    collect_sysvol: bool = True
    ca_file: str | None = None
    tls_no_verify: bool = False
    # Broad collection is intentionally opt-in because target authorization
    # resolution can otherwise create substantial DC load.
    allow_all_targets: bool = False
    connect_timeout: float = 10.0
    receive_timeout: float = 30.0
    ldap_page_size: int = 500
    max_ldap_queries: int = 5000
    max_group_queries: int = 1000
    retry_limit: int = 2
    retry_backoff: float = 0.5
    smb_timeout: float = 30.0
    max_sysvol_file_bytes: int = 64 * 1024 * 1024
    max_sysvol_total_bytes: int = 512 * 1024 * 1024
    max_sysvol_files: int = 10_000
    max_sysvol_probes: int = 15_000

    def __post_init__(self) -> None:
        positive = {
            "connect_timeout": self.connect_timeout,
            "receive_timeout": self.receive_timeout,
            "ldap_page_size": self.ldap_page_size,
            "max_ldap_queries": self.max_ldap_queries,
            "max_group_queries": self.max_group_queries,
            "smb_timeout": self.smb_timeout,
            "max_sysvol_file_bytes": self.max_sysvol_file_bytes,
            "max_sysvol_total_bytes": self.max_sysvol_total_bytes,
            "max_sysvol_files": self.max_sysvol_files,
            "max_sysvol_probes": self.max_sysvol_probes,
        }
        invalid = [name for name, value in positive.items() if value <= 0]
        if invalid:
            raise ValueError(
                "collection limits must be positive: " + ", ".join(invalid)
            )
        if self.retry_limit < 0 or self.retry_backoff < 0:
            raise ValueError("LDAP retry limit/backoff cannot be negative")

    @property
    def base_dn(self) -> str:
        return ",".join(f"DC={label}" for label in self.domain.split(".") if label)


def _parent_dn(dn: str) -> str | None:
    escaped = False
    for index, character in enumerate(dn):
        if character == "\\":
            escaped = not escaped
            continue
        if character == "," and not escaped:
            return dn[index + 1 :]
        escaped = False
    return None


def _dns_domain_from_dn(dn: str) -> str | None:
    labels = [part[3:] for part in dn.split(",") if part[:3].casefold() == "dc="]
    return ".".join(labels) if labels else None


def _first(value: Any, default: Any = None) -> Any:
    if value is None:
        return default
    if isinstance(value, (list, tuple)):
        return value[0] if value else default
    return value


def _raw(entry: dict[str, Any], name: str) -> list[bytes]:
    values = entry.get("raw_attributes", {}).get(name, [])
    if values is None:
        return []
    return list(values) if isinstance(values, (list, tuple)) else [values]


def _sid(raw: bytes | str | None) -> str | None:
    if raw is None:
        return None
    if isinstance(raw, str):
        return raw
    try:
        from impacket.ldap.ldaptypes import LDAP_SID  # type: ignore[import-not-found]

        return LDAP_SID(data=bytes(raw)).formatCanonical()
    except Exception:
        return None


def _sid_filter(sid: str) -> str:
    parts = normalize_sid(sid).split("-")
    if len(parts) < 4 or parts[0] != "S":
        raise ValueError(f"invalid SID {sid!r}")
    try:
        revision = int(parts[1])
        authority = int(parts[2])
        subauthorities = [int(part) for part in parts[3:]]
    except ValueError as exc:
        raise ValueError(f"invalid SID {sid!r}") from exc
    if not 0 <= revision <= 0xFF or not 0 <= authority <= 0xFFFFFFFFFFFF:
        raise ValueError(f"invalid SID {sid!r}")
    if len(subauthorities) > 0xFF or any(
        not 0 <= item <= 0xFFFFFFFF for item in subauthorities
    ):
        raise ValueError(f"invalid SID {sid!r}")
    data = bytes((revision, len(subauthorities)))
    data += authority.to_bytes(6, "big")
    data += b"".join(item.to_bytes(4, "little") for item in subauthorities)
    return "".join(f"\\{byte:02x}" for byte in data)


def _escape_filter_value(value: str) -> str:
    """Escape a text assertion value according to RFC 4515."""

    escapes = {"\\": r"\5c", "*": r"\2a", "(": r"\28", ")": r"\29", "\0": r"\00"}
    return "".join(escapes.get(character, character) for character in value)


def _primary_group_sid(object_sid: str, primary_group_id: Any) -> str | None:
    try:
        normalized = normalize_sid(object_sid)
        parts = normalized.split("-")
        if len(parts) < 8 or parts[:4] != ["S", "1", "5", "21"]:
            return None
        domain_sid, _rid = normalized.rsplit("-", 1)
        rid = int(primary_group_id)
    except (AttributeError, TypeError, ValueError):
        return None
    if not 0 <= rid <= 0xFFFFFFFF:
        return None
    return f"{domain_sid}-{rid}"


def _trustee_object_kind(object_classes: Any) -> str:
    values = (object_classes,) if isinstance(object_classes, str) else object_classes
    try:
        classes = {str(value).casefold() for value in values}
    except TypeError:
        classes = set()
    if "group" in classes:
        return "group"
    if "foreignsecurityprincipal" in classes:
        return "foreign"
    return "non-group"


def _token_sids(entry: dict[str, Any]) -> tuple[str, ...]:
    # SELF (S-1-5-10) is deliberately NOT added: in an AD access check the DC
    # substitutes a SELF ACE with the SID of the object being evaluated, so it
    # is not a universal token membership of an arbitrary principal.
    values = [EVERYONE, AUTHENTICATED_USERS]
    values.extend(filter(None, (_sid(value) for value in _raw(entry, "objectSid"))))
    values.extend(filter(None, (_sid(value) for value in _raw(entry, "sIDHistory"))))
    values.extend(filter(None, (_sid(value) for value in _raw(entry, "tokenGroups"))))
    return unique_normalized_sids(values)


def _token_complete(entry: dict[str, Any]) -> bool:
    """True when tokenGroups was actually returned for this object.

    A missing tokenGroups attribute means the group token could not be fully
    enumerated; the caller must then fail the derived findings closed rather
    than silently trusting an undercounted token.
    """
    raw = entry.get("raw_attributes", {})
    return "tokenGroups" in raw and bool(raw.get("tokenGroups"))


def _relevant_gpo_trustee_sids(gpos: dict[str, GPO]) -> set[str]:
    """Return every trustee whose membership can affect GPO applicability.

    Unsupported ACEs must be included regardless of their parsed mask. Callback
    ACE parsers commonly expose a zero mask; dropping that trustee would make a
    target that belongs to it look safely authorized instead of UNKNOWN.
    """

    relevant: set[str] = set()
    ignored = {EVERYONE, AUTHENTICATED_USERS, "S-1-3-4", "S-1-5-10"}
    selected_rights = (
        DIRECTORY_GENERIC_READ
        | ADS_RIGHT_DS_CONTROL_ACCESS
        | GENERIC_READ
        | GENERIC_ALL
    )
    for gpo in gpos.values():
        for ace in gpo.security_descriptor.aces:
            if not ace.trustee_sid:
                continue
            sid = normalize_sid(ace.trustee_sid)
            if sid in ignored:
                continue
            if ace.ace_type is AceType.UNSUPPORTED or ace.access_mask & selected_rights:
                relevant.add(sid)
    return relevant


class LDAPCollector:
    def __init__(self, config: CollectionConfig):
        self.config = config
        self.warnings: list[str] = []
        self.ldap_endpoint: str | None = None
        self.ldap_peer_ip: str | None = None
        self.tls_verified: bool | None = None
        self._query_count = 0
        self._group_query_count = 0
        self.connection = self._connect()

    def _reserve_group_query(self) -> bool:
        count = getattr(self, "_group_query_count", 0)
        if count >= self.config.max_group_queries:
            return False
        self._group_query_count = count + 1
        return True

    def _connect(self):
        try:
            from ldap3 import (  # type: ignore[import-not-found]
                KERBEROS,
                ENCRYPT,
                NONE,
                NTLM,
                SASL,
                SIMPLE,
                Connection,
                Server,
                Tls,
                TLS_CHANNEL_BINDING,
            )
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise RuntimeError(
                "live collection requires the 'collect' extra (ldap3 and impacket)"
            ) from exc

        uri = (
            self.config.ldap_uri or f"ldap://{self.config.dc_host or self.config.dc_ip}"
        )
        parsed = urlparse(uri)
        if parsed.scheme.casefold() not in {"ldap", "ldaps"}:
            raise RuntimeError("--ldap-uri must use ldap:// or ldaps://")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise RuntimeError(
                "--ldap-uri must not contain credentials, query parameters, or fragments"
            )
        if parsed.path not in {"", "/"}:
            raise RuntimeError("--ldap-uri must not contain a base-DN path")
        use_ssl = parsed.scheme.casefold() == "ldaps"
        if not use_ssl and (self.config.ca_file or self.config.tls_no_verify):
            raise RuntimeError("--ca-file/--tls-no-verify require an ldaps:// URI")
        host = parsed.hostname or self.config.dc_ip
        port = parsed.port or (636 if use_ssl else 389)
        tls = None
        if use_ssl:
            tls = Tls(
                validate=ssl.CERT_NONE
                if self.config.tls_no_verify
                else ssl.CERT_REQUIRED,
                ca_certs_file=self.config.ca_file,
            )
            self.tls_verified = not self.config.tls_no_verify
            if self.config.tls_no_verify:
                self.warnings.append(
                    "TLS certificate verification disabled by --tls-no-verify; "
                    "the LDAP server identity is not authenticated"
                )
        else:
            self.tls_verified = False
        server = Server(
            host,
            port=port,
            use_ssl=use_ssl,
            tls=tls,
            get_info=NONE,
            connect_timeout=self.config.connect_timeout,
        )
        auth = self.config.auth
        if auth.kerberos:
            user = auth.username
            connection = Connection(
                server,
                user=user or None,
                password=auth.password or None,
                authentication=SASL,
                sasl_mechanism=KERBEROS,
                sasl_credentials=(self.config.dc_host or self.config.domain,),
                auto_bind=True,
                raise_exceptions=True,
                receive_timeout=self.config.receive_timeout,
                auto_referrals=False,
                read_only=True,
            )
        elif auth.username:
            user = auth.username
            authentication = SIMPLE
            password = auth.password
            if auth.auth_domain and "\\" not in user and "@" not in user:
                user = f"{auth.auth_domain}\\{user}"
                authentication = NTLM
            if auth.nthash:
                password = f"{auth.lmhash or EMPTY_LM_HASH}:{auth.nthash}"
            if (
                authentication == SIMPLE
                and not use_ssl
                and not auth.allow_insecure_simple_bind
            ):
                raise RuntimeError(
                    "refusing to send a SIMPLE bind password over a cleartext "
                    "ldap:// connection. Use LDAPS (--ldap-uri ldaps://...), "
                    "Kerberos/NTLM (supply --auth-domain for NTLM), or pass "
                    "--allow-insecure-simple-bind to override."
                )
            ntlm_security: dict[str, Any] = {}
            if authentication == NTLM:
                if use_ssl:
                    ntlm_security["channel_binding"] = TLS_CHANNEL_BINDING
                else:
                    ntlm_security["session_security"] = ENCRYPT
            connection = Connection(
                server,
                user=user,
                password=password,
                authentication=authentication,
                auto_bind=True,
                raise_exceptions=True,
                receive_timeout=self.config.receive_timeout,
                auto_referrals=False,
                read_only=True,
                **ntlm_security,
            )
        else:
            connection = Connection(
                server,
                auto_bind=True,
                raise_exceptions=True,
                receive_timeout=self.config.receive_timeout,
                auto_referrals=False,
                read_only=True,
            )
        peer = None
        try:
            peer = str(connection.socket.getpeername()[0])
        except Exception:
            peer = None
        self.ldap_peer_ip = peer
        self.ldap_endpoint = f"{parsed.scheme.casefold()}://{host}:{port}"
        if peer:
            self.ldap_endpoint += f" (peer {peer})"
            try:
                same_peer = ip_address(peer) == ip_address(self.config.dc_ip)
            except ValueError:
                same_peer = peer.casefold() == self.config.dc_ip.casefold()
            if not same_peer:
                raise RuntimeError(
                    f"LDAP connected to {peer}, but SYSVOL is pinned to "
                    f"{self.config.dc_ip}; refusing a cross-DC snapshot"
                )
        else:
            self.warnings.append(
                "LDAP peer endpoint could not be verified; same-DC provenance is incomplete"
            )
        return connection

    def _search(
        self,
        base: str,
        ldap_filter: str,
        attributes: list[str],
        *,
        scope: str = "SUBTREE",
        security_descriptor: bool = False,
    ) -> list[dict[str, Any]]:
        from ldap3 import BASE, SUBTREE  # type: ignore[import-not-found]

        controls = None
        if security_descriptor:
            from ldap3.protocol.microsoft import security_descriptor_control  # type: ignore[import-not-found]

            controls = security_descriptor_control(sdflags=_SD_FLAGS_OWNER_DACL)
        for attempt in range(self.config.retry_limit + 1):
            if self._query_count >= self.config.max_ldap_queries:
                raise RuntimeError(
                    f"LDAP query budget exhausted ({self.config.max_ldap_queries})"
                )
            self._query_count += 1
            try:
                generator = self.connection.extend.standard.paged_search(
                    search_base=base,
                    search_filter=ldap_filter,
                    search_scope=BASE if scope == "BASE" else SUBTREE,
                    attributes=attributes,
                    paged_size=self.config.ldap_page_size,
                    generator=True,
                    controls=controls,
                )
                return [
                    entry
                    for entry in generator
                    if entry.get("type") == "searchResEntry"
                ]
            except Exception:
                if attempt >= self.config.retry_limit:
                    raise
                time.sleep(self.config.retry_backoff * (2**attempt))
        raise AssertionError("unreachable LDAP retry state")

    def _root_dse(self) -> tuple[str, str, str]:
        entries = self._search(
            "",
            "(objectClass=*)",
            [
                "defaultNamingContext",
                "configurationNamingContext",
                "rootDomainNamingContext",
            ],
            scope="BASE",
        )
        if not entries:
            raise RuntimeError("RootDSE did not return naming contexts")
        attrs = entries[0]["attributes"]
        default_dn = str(_first(attrs.get("defaultNamingContext")))
        return (
            default_dn,
            str(_first(attrs.get("configurationNamingContext"))),
            str(_first(attrs.get("rootDomainNamingContext"), default_dn)),
        )

    def _domain_sid(self, domain_dn: str) -> str | None:
        entries = self._search(
            domain_dn,
            "(objectClass=domainDNS)",
            ["objectSid"],
            scope="BASE",
        )
        if not entries:
            self.warnings.append(f"domain SID was not returned for {domain_dn}")
            return None
        sid = _sid(_first(_raw(entries[0], "objectSid")))
        if sid is None:
            self.warnings.append(f"domain SID was unreadable for {domain_dn}")
        return sid

    def _domain_netbios_name(
        self, domain_dn: str, configuration_dn: str
    ) -> str | None:
        entries = self._search(
            f"CN=Partitions,{configuration_dn}",
            "(&(objectClass=crossRef)"
            f"(nCName={_escape_filter_value(domain_dn)}))",
            ["nETBIOSName"],
        )
        names = {
            str(_first(entry.get("attributes", {}).get("nETBIOSName"))).strip()
            for entry in entries
            if _first(entry.get("attributes", {}).get("nETBIOSName"))
        }
        if len(names) != 1:
            self.warnings.append(
                f"domain NetBIOS name was not uniquely returned for {domain_dn}"
            )
            return None
        return names.pop()

    @staticmethod
    def _descriptor(entry: dict[str, Any]):
        # GPOWake evaluates domainDNS, OU, site and groupPolicyContainer
        # objects here, not computer-derived objects. BlockOwnerImplicitRights
        # therefore does not suppress owner rights for these descriptors.
        return parse_security_descriptor(
            _first(_raw(entry, "nTSecurityDescriptor")),
            owner_implicit_rights_verified=True,
        )

    def _collect_soms(
        self, base_dn: str, configuration_dn: str
    ) -> tuple[dict[str, ScopeOfManagement], dict[str, str]]:
        attrs = [
            "distinguishedName",
            "gPLink",
            "gPOptions",
            "name",
            "nTSecurityDescriptor",
        ]
        entries = self._search(
            base_dn,
            "(objectClass=domainDNS)",
            attrs,
            scope="BASE",
            security_descriptor=True,
        )
        entries += self._search(
            base_dn, "(objectClass=organizationalUnit)", attrs, security_descriptor=True
        )
        sites = self._search(
            f"CN=Sites,{configuration_dn}",
            "(objectClass=site)",
            attrs,
            security_descriptor=True,
        )
        entries += sites
        soms: dict[str, ScopeOfManagement] = {}
        site_names: dict[str, str] = {}
        for entry in entries:
            data = entry["attributes"]
            dn = entry["dn"]
            if normalize_dn(dn) == normalize_dn(base_dn):
                kind = SomKind.DOMAIN
                parent = None
            elif entry in sites:
                kind = SomKind.SITE
                parent = None
                site_names[str(_first(data.get("name"), "")).casefold()] = dn
            else:
                kind = SomKind.OU
                parent = _parent_dn(dn)
                while (
                    parent
                    and normalize_dn(parent) != normalize_dn(base_dn)
                    and not parent.casefold().startswith("ou=")
                ):
                    parent = _parent_dn(parent)
            gp_link = _first(data.get("gPLink"), "")
            try:
                links = parse_gplink(str(gp_link))
            except ValueError as exc:
                self.warnings.append(f"{dn}: {exc}")
                links = ()
            som = ScopeOfManagement(
                dn=dn,
                kind=kind,
                parent_dn=parent,
                links=links,
                gp_options=int(_first(data.get("gPOptions"), 0) or 0),
                security_descriptor=self._descriptor(entry),
            )
            soms[normalize_dn(dn)] = som
        return soms, site_names

    def _collect_gpos(self, base_dn: str) -> dict[str, GPO]:
        attrs = [
            "displayName",
            "name",
            "flags",
            "gPCFileSysPath",
            "gPCWQLFilter",
            "gPCMachineExtensionNames",
            "gPCFunctionalityVersion",
            "versionNumber",
            "uSNChanged",
            "nTSecurityDescriptor",
        ]
        entries = self._search(
            f"CN=Policies,CN=System,{base_dn}",
            "(objectClass=groupPolicyContainer)",
            attrs,
            security_descriptor=True,
        )
        gpos: dict[str, GPO] = {}
        for entry in entries:
            data = entry["attributes"]
            guid = str(_first(data.get("name"), entry["dn"].split(",", 1)[0][3:]))
            extension_raw = data.get("gPCMachineExtensionNames")
            extensions = tuple(
                dict.fromkeys(
                    match.group(1).lower()
                    for match in _GUID_RE.finditer(str(_first(extension_raw, "")))
                )
            )
            file_path = str(_first(data.get("gPCFileSysPath"), ""))
            functionality_raw = _first(data.get("gPCFunctionalityVersion"))
            gpo = GPO(
                dn=entry["dn"],
                guid=guid,
                name=str(_first(data.get("displayName"), guid)),
                flags=int(_first(data.get("flags"), 0) or 0),
                functionality_version=(
                    int(functionality_raw)
                    if functionality_raw is not None
                    else None
                ),
                file_sys_path=file_path,
                machine_extensions=extensions,
                security_descriptor=self._descriptor(entry),
                settings_complete=False,
                settings_uncertainty_reasons=(
                    "SYSVOL policy files have not been collected",
                ),
                incomplete_setting_kinds=tuple(SettingKind),
                wmi_filter=str(_first(data.get("gPCWQLFilter")))
                if data.get("gPCWQLFilter")
                else None,
                version_number=int(_first(data.get("versionNumber"), 0) or 0),
                usn_changed=int(_first(data.get("uSNChanged"), 0) or 0),
            )
            gpos[normalize_dn(gpo.dn)] = gpo
        return gpos

    def _entry_with_tokens(self, entry: dict[str, Any]) -> dict[str, Any]:
        token_entry = self._search(
            entry["dn"],
            "(objectClass=*)",
            [
                "objectSid",
                "sIDHistory",
                "tokenGroups",
                "sAMAccountName",
                "userPrincipalName",
                "name",
            ],
            scope="BASE",
        )
        return token_entry[0] if token_entry else entry

    def _collect_principals(self, base_dn: str) -> list[Principal]:
        from ldap3.utils.conv import escape_filter_chars  # type: ignore[import-not-found]

        principals: list[Principal] = []
        for requested in self.config.principals:
            if requested.upper().startswith("S-1-"):
                ldap_filter = f"(objectSid={_sid_filter(requested)})"
            elif "=" in requested and "," in requested:
                ldap_filter = f"(distinguishedName={escape_filter_chars(requested)})"
            else:
                escaped = escape_filter_chars(requested)
                ldap_filter = (
                    f"(|(sAMAccountName={escaped})(userPrincipalName={escaped}))"
                )
            entries = self._search(
                base_dn,
                ldap_filter,
                ["objectSid", "sAMAccountName", "userPrincipalName", "name"],
            )
            if not entries:
                raise RuntimeError(f"principal {requested!r} was not found")
            entry = self._entry_with_tokens(entries[0])
            sid = _sid(_first(_raw(entry, "objectSid")))
            if not sid:
                raise RuntimeError(f"principal {requested!r} has no readable objectSid")
            attrs = entry["attributes"]
            name = str(
                _first(
                    attrs.get("sAMAccountName"),
                    _first(attrs.get("userPrincipalName"), requested),
                )
            )
            complete = _token_complete(entry)
            if not complete:
                self.warnings.append(
                    f"tokenGroups unreadable for principal {name}; group-derived "
                    "rights may be undercounted, so authorization-dependent "
                    "paths are treated as coverage gaps"
                )
            principals.append(
                Principal(
                    sid, name, _token_sids(entry), token_incomplete=not complete
                )
            )
        return principals

    @staticmethod
    def _target_selected(
        entry: dict[str, Any], selection: tuple[str, ...]
    ) -> bool:
        if not selection:
            return True
        choices = {value.casefold() for value in selection}
        attrs = entry["attributes"]
        candidates = {entry["dn"].casefold()}
        for key in ("dNSHostName", "sAMAccountName", "name"):
            value = _first(attrs.get(key))
            if value:
                candidates.add(str(value).casefold())
        sid = _sid(_first(_raw(entry, "objectSid")))
        if sid:
            candidates.add(sid.casefold())
        return bool(candidates & choices)

    @staticmethod
    def _target_selection_filter(
        base_filter: str, selection: tuple[str, ...]
    ) -> str:
        """Combine the base filter with exact server-side target selectors."""

        if not selection:
            return base_filter
        from ldap3.utils.conv import escape_filter_chars  # type: ignore[import-not-found]

        clauses: list[str] = []
        for requested in selection:
            if requested.upper().startswith("S-1-"):
                clauses.append(f"(objectSid={_sid_filter(requested)})")
                continue
            escaped = escape_filter_chars(requested)
            clauses.extend(
                f"({attribute}={escaped})"
                for attribute in (
                    "distinguishedName",
                    "dNSHostName",
                    "sAMAccountName",
                    "name",
                )
            )
        return f"(&{base_filter}(|{''.join(clauses)}))"

    @staticmethod
    def _nearest_som(dn: str, soms: dict[str, ScopeOfManagement], base_dn: str) -> str:
        parent = _parent_dn(dn)
        while parent:
            if normalize_dn(parent) in soms:
                return soms[normalize_dn(parent)].dn
            parent = _parent_dn(parent)
        return base_dn

    def _collect_targets(
        self,
        base_dn: str,
        soms: dict[str, ScopeOfManagement],
        site_names: dict[str, str],
        gpos: dict[str, GPO],
        dns_domain: str | None,
        netbios_domain: str | None,
    ) -> list[Target]:
        if not self.config.target_names and not self.config.allow_all_targets:
            raise RuntimeError(
                "broad target collection requires the explicit allow_all_targets flag"
            )
        attrs = [
            "objectSid",
            "sIDHistory",
            "sAMAccountName",
            "dNSHostName",
            "name",
            "userAccountControl",
            "msDS-SiteName",
            "primaryGroupID",
        ]
        selection = self.config.target_names
        entries = self._search(
            base_dn,
            self._target_selection_filter(self.config.target_filter, selection),
            attrs,
        )
        entries = [
            entry for entry in entries if self._target_selected(entry, selection)
        ]
        relevant_sids = _relevant_gpo_trustee_sids(gpos)
        direct_target_sids = {
            normalize_sid(sid)
            for entry in entries
            for attribute in ("objectSid", "sIDHistory")
            for sid in filter(None, (_sid(value) for value in _raw(entry, attribute)))
        }
        relevant_sids -= direct_target_sids
        primary_groups: dict[str, str | None] = {}
        for entry in entries:
            sid = _sid(_first(_raw(entry, "objectSid")))
            group_id = _first(entry.get("attributes", {}).get("primaryGroupID"))
            primary_groups[normalize_dn(entry["dn"])] = (
                _primary_group_sid(sid, group_id)
                if sid and group_id is not None
                else None
            )
        primary_ancestry, unresolved_primary_groups = (
            self._primary_group_ancestry(
                base_dn,
                {sid for sid in primary_groups.values() if sid},
            )
        )
        memberships, unresolved, possible_group_sids = self._target_group_memberships(
            base_dn, selection, relevant_sids
        )
        targets: list[Target] = []
        for original in entries:
            sid = _sid(_first(_raw(original, "objectSid")))
            if not sid:
                self.warnings.append(
                    f"target {original['dn']} has no readable SID and was skipped"
                )
                continue
            attrs = original["attributes"]
            sam_account_name = str(
                _first(attrs.get("sAMAccountName"), "")
            ).strip() or None
            if sam_account_name is None:
                self.warnings.append(
                    f"target {original['dn']} has no readable sAMAccountName; "
                    "machine identity cannot be attested"
                )
            name = str(
                _first(
                    attrs.get("dNSHostName"),
                    _first(attrs.get("sAMAccountName"), original["dn"]),
                )
            )
            site_name = str(_first(attrs.get("msDS-SiteName"), ""))
            site_dn = site_names.get(site_name.casefold()) if site_name else None
            site_resolution_error = None
            if not site_dn:
                site_resolution_error = (
                    f"site unknown for target {name}; site-linked policy can alter "
                    "LSDOU precedence"
                )
                self.warnings.append(site_resolution_error)
            target_unresolved = set(unresolved)
            primary_group_sid = primary_groups.get(normalize_dn(original["dn"]))
            if primary_group_sid is None:
                target_unresolved.update(possible_group_sids)
                self.warnings.append(
                    f"primaryGroupID is unreadable for target {name}; "
                    "primary-group ancestry is unknown"
                )
            elif primary_group_sid in unresolved_primary_groups:
                target_unresolved.update(possible_group_sids)
                self.warnings.append(
                    f"primary-group ancestry is incomplete for target {name}; "
                    "ACL-referenced group membership is treated as UNKNOWN"
                )
            if target_unresolved:
                self.warnings.append(
                    f"referenced-group resolution is incomplete for target {name}; "
                    "only DACLs naming those trustees are treated as UNKNOWN"
                )
            uac = int(_first(attrs.get("userAccountControl"), 0) or 0)
            token_sids = set(_token_sids(original))
            if primary_group_sid:
                token_sids.add(primary_group_sid)
                token_sids.update(
                    primary_ancestry.get(primary_group_sid, set()) & relevant_sids
                )
            token_sids.update(memberships.get(normalize_dn(original["dn"]), set()))
            targets.append(
                Target(
                    dn=original["dn"],
                    name=name,
                    sid=sid,
                    som_dn=self._nearest_som(original["dn"], soms, base_dn),
                    token_sids=unique_normalized_sids(sorted(token_sids)),
                    sam_account_name=sam_account_name,
                    dns_domain=dns_domain,
                    netbios_domain=netbios_domain,
                    site_dn=site_dn,
                    criticality="DOMAIN_CONTROLLER" if uac & 0x2000 else "NORMAL",
                    token_incomplete=False,
                    unresolved_token_sids=unique_normalized_sids(
                        sorted(target_unresolved)
                    ),
                    site_resolution_error=site_resolution_error,
                )
            )
        return targets

    def _primary_group_ancestry(
        self,
        base_dn: str,
        primary_group_sids: set[str],
    ) -> tuple[dict[str, set[str]], set[str]]:
        """Resolve parent-group closure for each distinct primary group SID."""

        if not primary_group_sids:
            return {}, set()
        group_dns: dict[str, str] = {}
        unresolved: set[str] = set()
        sid_list = sorted(primary_group_sids)
        for start in range(0, len(sid_list), 50):
            chunk = sid_list[start : start + 50]
            sid_filter = "".join(f"(objectSid={_sid_filter(sid)})" for sid in chunk)
            try:
                entries = self._search(
                    base_dn,
                    f"(&(objectClass=group)(|{sid_filter}))",
                    ["objectSid", "distinguishedName"],
                )
            except Exception as exc:
                unresolved.update(chunk)
                self.warnings.append(
                    "could not resolve primary-group SID batch: " + str(exc)
                )
                continue
            returned: set[str] = set()
            for entry in entries:
                sid = _sid(_first(_raw(entry, "objectSid")))
                if sid:
                    normalized = normalize_sid(sid)
                    returned.add(normalized)
                    group_dns[normalized] = entry["dn"]
            unresolved.update(set(chunk) - returned)

        ancestry: dict[str, set[str]] = {}
        items = sorted(group_dns.items())
        for index, (primary_sid, group_dn) in enumerate(items):
            if not self._reserve_group_query():
                unresolved.update(sid for sid, _dn in items[index:])
                self.warnings.append(
                    "recursive group query budget reached while resolving "
                    "primary-group ancestry"
                )
                break
            recursive = (
                "(&(objectClass=group)"
                "(member:1.2.840.113556.1.4.1941:="
                f"{_escape_filter_value(group_dn)}))"
            )
            try:
                entries = self._search(base_dn, recursive, ["objectSid"])
            except Exception as exc:
                unresolved.add(primary_sid)
                self.warnings.append(
                    f"could not resolve ancestry for primary group {primary_sid}: {exc}"
                )
                continue
            parents: set[str] = set()
            malformed = False
            for entry in entries:
                parent_sid = _sid(_first(_raw(entry, "objectSid")))
                if parent_sid:
                    parents.add(normalize_sid(parent_sid))
                else:
                    malformed = True
            if malformed:
                unresolved.add(primary_sid)
                self.warnings.append(
                    f"primary-group ancestry for {primary_sid} returned a group "
                    "without a readable SID"
                )
            ancestry[primary_sid] = parents
        return ancestry, unresolved

    def _target_group_memberships(
        self,
        base_dn: str,
        selection: tuple[str, ...],
        relevant_sids: set[str],
    ) -> tuple[dict[str, set[str]], set[str], set[str]]:
        """Resolve only ACL-referenced group membership, group-first.

        This replaces one expensive constructed ``tokenGroups`` query per
        computer with one recursive membership query per relevant GPO trustee.
        """

        if not relevant_sids:
            return {}, set(), set()
        sid_list = sorted(relevant_sids)
        groups: dict[str, str] = {}
        resolved_objects: set[str] = set()
        unresolved: set[str] = set()
        for start in range(0, len(sid_list), 50):
            chunk = sid_list[start : start + 50]
            sid_filter = "".join(f"(objectSid={_sid_filter(sid)})" for sid in chunk)
            try:
                entries = self._search(
                    base_dn,
                    f"(|{sid_filter})",
                    ["objectSid", "distinguishedName", "objectClass"],
                )
            except Exception as exc:
                unresolved.update(chunk)
                self.warnings.append(
                    "could not resolve ACL trustee SID batch: " + str(exc)
                )
                continue
            for entry in entries:
                sid = _sid(_first(_raw(entry, "objectSid")))
                if sid:
                    normalized = normalize_sid(sid)
                    classes = entry.get("attributes", {}).get("objectClass", ())
                    object_kind = _trustee_object_kind(classes)
                    if object_kind == "group":
                        resolved_objects.add(normalized)
                        groups[normalized] = entry["dn"]
                    elif object_kind == "non-group":
                        # Local non-group trustees cannot be transitive group
                        # memberships of a selected computer. Foreign security
                        # principals are intentionally left unresolved because
                        # their remote object type/token expansion is unknown.
                        resolved_objects.add(normalized)

        memberships: dict[str, set[str]] = {}
        unresolved.update(set(relevant_sids) - resolved_objects)
        group_items = sorted(groups.items())
        for index, (sid, group_dn) in enumerate(group_items):
            if not self._reserve_group_query():
                skipped = group_items[index:]
                unresolved.update(item_sid for item_sid, _group_dn in skipped)
                self.warnings.append(
                    "recursive group query budget reached; skipped "
                    f"{len(skipped)} ACL trustee(s)"
                )
                break
            recursive = (
                "(memberOf:1.2.840.113556.1.4.1941:="
                f"{_escape_filter_value(group_dn)})"
            )
            target_filter = f"(&{self.config.target_filter}{recursive})"
            target_filter = self._target_selection_filter(target_filter, selection)
            try:
                entries = self._search(base_dn, target_filter, ["objectSid"])
            except Exception as exc:
                unresolved.add(sid)
                self.warnings.append(
                    f"could not resolve recursive membership for {sid}: {exc}"
                )
                continue
            for entry in entries:
                memberships.setdefault(normalize_dn(entry["dn"]), set()).add(sid)
        if unresolved:
            self.warnings.append(
                "GPO ACL trustees could not all be resolved as in-domain groups: "
                + ", ".join(sorted(unresolved))
            )
        return memberships, unresolved, set(groups).union(unresolved)

    def collect(self) -> Environment:
        base_dn, configuration_dn, forest_root_dn = self._root_dse()
        if normalize_dn(base_dn) != normalize_dn(self.config.base_dn):
            self.warnings.append(
                f"requested domain maps to {self.config.base_dn}, but RootDSE returned {base_dn}"
            )
        soms, site_names = self._collect_soms(base_dn, configuration_dn)
        gpos = self._collect_gpos(base_dn)
        principals = self._collect_principals(base_dn)
        dns_domain = _dns_domain_from_dn(base_dn)
        netbios_domain = self._domain_netbios_name(base_dn, configuration_dn)
        targets = self._collect_targets(
            base_dn,
            soms,
            site_names,
            gpos,
            dns_domain,
            netbios_domain,
        )
        domain_sid = self._domain_sid(base_dn)
        forest_root_sid = (
            domain_sid
            if normalize_dn(base_dn) == normalize_dn(forest_root_dn)
            else self._domain_sid(forest_root_dn)
        )
        self.warnings.append(
            "LDAP signing/channel-binding policy was not remotely attested; "
            "transport/authentication details are recorded for operator review"
        )
        return Environment(
            soms=soms,
            gpos=gpos,
            principals=principals,
            targets=targets,
            source_dc=self.config.dc_host or self.config.dc_ip,
            warnings=self.warnings,
            ldap_endpoint=self.ldap_endpoint,
            smb_endpoint=(
                f"smb://{self.config.dc_host or self.config.domain} "
                f"(peer {self.config.dc_ip})"
                if self.config.collect_sysvol
                else None
            ),
            tls_verified=self.tls_verified,
            collected_at=datetime.now(timezone.utc).isoformat(),
            domain_sid=domain_sid,
            forest_root_sid=forest_root_sid,
        )


def collect_environment(config: CollectionConfig) -> Environment:
    environment = LDAPCollector(config).collect()
    if config.collect_sysvol:
        from .sysvol import collect_sysvol

        environment = collect_sysvol(environment, config)
    return environment
