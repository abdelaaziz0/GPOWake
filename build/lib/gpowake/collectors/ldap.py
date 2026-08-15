from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from ..acl import parse_security_descriptor
from ..gplink import parse_gplink
from ..models import (
    Environment,
    GPO,
    Principal,
    ScopeOfManagement,
    SomKind,
    Target,
    normalize_dn,
    unique_normalized_sids,
)


EVERYONE = "S-1-1-0"
AUTHENTICATED_USERS = "S-1-5-11"
SELF = "S-1-5-10"
EMPTY_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"
_GUID_RE = re.compile(r"\{([0-9a-fA-F-]{36})\}")


@dataclass(frozen=True)
class AuthConfig:
    username: str = ""
    password: str = ""
    auth_domain: str = ""
    lmhash: str = ""
    nthash: str = ""
    kerberos: bool = False
    ccache: str | None = None


@dataclass(frozen=True)
class CollectionConfig:
    domain: str
    dc_ip: str
    dc_host: str | None = None
    ldap_uri: str | None = None
    principals: tuple[str, ...] = ()
    target_filter: str = "(objectCategory=computer)"
    auth: AuthConfig = AuthConfig()
    collect_sysvol: bool = True

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
    from impacket.ldap.ldaptypes import LDAP_SID  # type: ignore[import-not-found]

    parsed = LDAP_SID()
    parsed.fromCanonical(sid)
    return "".join(f"\\{byte:02x}" for byte in parsed.getData())


def _token_sids(entry: dict[str, Any]) -> tuple[str, ...]:
    values = [EVERYONE, AUTHENTICATED_USERS, SELF]
    values.extend(filter(None, (_sid(value) for value in _raw(entry, "objectSid"))))
    values.extend(filter(None, (_sid(value) for value in _raw(entry, "sIDHistory"))))
    values.extend(filter(None, (_sid(value) for value in _raw(entry, "tokenGroups"))))
    return unique_normalized_sids(values)


class LDAPCollector:
    def __init__(self, config: CollectionConfig):
        self.config = config
        self.warnings: list[str] = []
        self.connection = self._connect()

    def _connect(self):
        try:
            from ldap3 import KERBEROS, NONE, NTLM, SASL, SIMPLE, Connection, Server  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise RuntimeError(
                "live collection requires the 'collect' extra (ldap3 and impacket)"
            ) from exc

        uri = (
            self.config.ldap_uri or f"ldap://{self.config.dc_host or self.config.dc_ip}"
        )
        parsed = urlparse(uri)
        use_ssl = parsed.scheme.casefold() == "ldaps"
        host = parsed.hostname or self.config.dc_ip
        server = Server(
            host,
            port=parsed.port or (636 if use_ssl else 389),
            use_ssl=use_ssl,
            get_info=NONE,
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
            connection = Connection(
                server,
                user=user,
                password=password,
                authentication=authentication,
                auto_bind=True,
                raise_exceptions=True,
            )
        else:
            connection = Connection(server, auto_bind=True, raise_exceptions=True)
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

            controls = security_descriptor_control(sdflags=0x04)
        generator = self.connection.extend.standard.paged_search(
            search_base=base,
            search_filter=ldap_filter,
            search_scope=BASE if scope == "BASE" else SUBTREE,
            attributes=attributes,
            paged_size=500,
            generator=True,
            controls=controls,
        )
        return [entry for entry in generator if entry.get("type") == "searchResEntry"]

    def _root_dse(self) -> tuple[str, str]:
        entries = self._search(
            "",
            "(objectClass=*)",
            ["defaultNamingContext", "configurationNamingContext"],
            scope="BASE",
        )
        if not entries:
            raise RuntimeError("RootDSE did not return naming contexts")
        attrs = entries[0]["attributes"]
        return str(_first(attrs.get("defaultNamingContext"))), str(
            _first(attrs.get("configurationNamingContext"))
        )

    @staticmethod
    def _descriptor(entry: dict[str, Any]):
        return parse_security_descriptor(_first(_raw(entry, "nTSecurityDescriptor")))

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
            gpo = GPO(
                dn=entry["dn"],
                guid=guid,
                name=str(_first(data.get("displayName"), guid)),
                flags=int(_first(data.get("flags"), 0) or 0),
                functionality_version=int(
                    _first(data.get("gPCFunctionalityVersion"), 0) or 0
                ),
                file_sys_path=file_path,
                machine_extensions=extensions,
                security_descriptor=self._descriptor(entry),
                wmi_filter=str(_first(data.get("gPCWQLFilter")))
                if data.get("gPCWQLFilter")
                else None,
                version_number=int(_first(data.get("versionNumber"), 0) or 0),
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
            principals.append(Principal(sid, name, _token_sids(entry)))
        return principals

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
    ) -> list[Target]:
        attrs = [
            "objectSid",
            "sAMAccountName",
            "dNSHostName",
            "name",
            "userAccountControl",
            "msDS-SiteName",
        ]
        entries = self._search(base_dn, self.config.target_filter, attrs)
        targets: list[Target] = []
        for original in entries:
            entry = self._entry_with_tokens(original)
            sid = _sid(_first(_raw(entry, "objectSid")))
            if not sid:
                self.warnings.append(
                    f"target {original['dn']} has no readable SID and was skipped"
                )
                continue
            attrs = original["attributes"]
            name = str(
                _first(
                    attrs.get("dNSHostName"),
                    _first(attrs.get("sAMAccountName"), original["dn"]),
                )
            )
            site_name = str(_first(attrs.get("msDS-SiteName"), ""))
            site_dn = site_names.get(site_name.casefold()) if site_name else None
            if not site_dn:
                self.warnings.append(
                    f"site unknown for target {name}; site-linked policy confidence is reduced"
                )
            uac = int(_first(attrs.get("userAccountControl"), 0) or 0)
            targets.append(
                Target(
                    dn=original["dn"],
                    name=name,
                    sid=sid,
                    som_dn=self._nearest_som(original["dn"], soms, base_dn),
                    token_sids=_token_sids(entry),
                    site_dn=site_dn,
                    criticality="DOMAIN_CONTROLLER" if uac & 0x2000 else "NORMAL",
                )
            )
        return targets

    def collect(self) -> Environment:
        base_dn, configuration_dn = self._root_dse()
        if normalize_dn(base_dn) != normalize_dn(self.config.base_dn):
            self.warnings.append(
                f"requested domain maps to {self.config.base_dn}, but RootDSE returned {base_dn}"
            )
        soms, site_names = self._collect_soms(base_dn, configuration_dn)
        gpos = self._collect_gpos(base_dn)
        principals = self._collect_principals(base_dn)
        targets = self._collect_targets(base_dn, soms, site_names)
        return Environment(
            soms=soms,
            gpos=gpos,
            principals=principals,
            targets=targets,
            source_dc=self.config.dc_host or self.config.dc_ip,
            warnings=self.warnings,
        )


def collect_environment(config: CollectionConfig) -> Environment:
    environment = LDAPCollector(config).collect()
    if config.collect_sysvol:
        from .sysvol import collect_sysvol

        environment = collect_sysvol(environment, config)
    return environment
