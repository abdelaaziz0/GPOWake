from __future__ import annotations

import ssl
import sys
from types import ModuleType, SimpleNamespace

import pytest

from gpowake.collectors.ldap import (
    CollectionConfig,
    AuthConfig,
    LDAPCollector,
    _parent_dn,
    _primary_group_sid,
    _relevant_gpo_trustee_sids,
    _trustee_object_kind,
)
from gpowake.collectors.sysvol import (
    collect_sysvol,
    _gpt_version,
    _unc_parts,
    _validated_gpt_location,
)
from gpowake.models import Ace, AceType, Environment, GPO, SecurityDescriptor, SettingKind


def test_parent_dn_honors_escaped_comma() -> None:
    assert _parent_dn(r"CN=Last\, First,OU=People,DC=corp,DC=local") == (
        "OU=People,DC=corp,DC=local"
    )


def test_sysvol_unc_and_version_parsing() -> None:
    share, path = _unc_parts(
        r"\\corp.local\SYSVOL\corp.local\Policies\{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"
    )
    assert share.casefold() == "sysvol"
    assert path.startswith("corp.local\\Policies")
    assert _gpt_version(b"[General]\r\nVersion=42\r\n") == 42
    assert _gpt_version(b"not-an-ini") is None


def test_sysvol_path_is_confined_to_the_expected_gpo() -> None:
    config = CollectionConfig(domain="corp.local", dc_ip="10.0.0.1")
    guid = "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"
    share, root = _validated_gpt_location(
        rf"\\corp.local\SYSVOL\corp.local\Policies\{guid}", config, guid
    )
    assert share.casefold() == "sysvol"
    assert root.endswith(guid)
    with pytest.raises(ValueError, match="outside SYSVOL Policies"):
        _validated_gpt_location(
            rf"\\corp.local\SYSVOL\corp.local\scripts\{guid}", config, guid
        )


def test_primary_group_and_foreign_trustee_classification() -> None:
    assert _primary_group_sid("S-1-5-21-1-2-3-2100", 515) == (
        "S-1-5-21-1-2-3-515"
    )
    assert _primary_group_sid("not-a-sid", "bad") is None
    assert _primary_group_sid("S-1-5-21-1-2-3-2100", 0x100000000) is None
    assert _trustee_object_kind(("top", "group")) == "group"
    assert _trustee_object_kind(("top", "foreignSecurityPrincipal")) == "foreign"
    assert _trustee_object_kind(("top", "user")) == "non-group"


def test_unsupported_zero_mask_ace_trustee_is_always_resolved() -> None:
    trustee = "S-1-5-21-1-2-3-2500"
    gpo = GPO(
        dn="CN={A},CN=Policies,DC=corp,DC=local",
        guid="{A}",
        name="callback",
        security_descriptor=SecurityDescriptor(
            aces=(Ace(trustee, AceType.UNSUPPORTED, 0),),
            has_unsupported_ace=True,
        ),
    )
    assert _relevant_gpo_trustee_sids({gpo.dn.casefold(): gpo}) == {trustee}


def test_primary_group_parent_ancestry_is_resolved(monkeypatch) -> None:
    primary = "S-1-5-21-1-2-3-515"
    parent = "S-1-5-21-1-2-3-2200"
    collector = object.__new__(LDAPCollector)
    collector.config = CollectionConfig(
        domain="corp.local", dc_ip="10.0.0.1", max_group_queries=2
    )
    collector.warnings = []
    collector._group_query_count = 0

    def fake_search(base, ldap_filter, attributes, **kwargs):
        if "(|(objectSid=" in ldap_filter:
            return [
                {
                    "dn": "CN=Domain Computers,CN=Users,DC=corp,DC=local",
                    "raw_attributes": {"objectSid": [primary]},
                }
            ]
        assert "1.2.840.113556.1.4.1941" in ldap_filter
        return [
            {
                "dn": "CN=Tier Zero,OU=Groups,DC=corp,DC=local",
                "raw_attributes": {"objectSid": [parent]},
            }
        ]

    monkeypatch.setattr(collector, "_search", fake_search)
    ancestry, unresolved = collector._primary_group_ancestry(
        "DC=corp,DC=local", {primary}
    )
    assert unresolved == set()
    assert ancestry == {primary: {parent}}


def test_resolved_non_group_trustee_is_not_primary_group_uncertainty(
    monkeypatch,
) -> None:
    trustee = "S-1-5-21-1-2-3-2300"
    collector = object.__new__(LDAPCollector)
    collector.config = CollectionConfig(domain="corp.local", dc_ip="10.0.0.1")
    collector.warnings = []
    collector._group_query_count = 0

    def fake_search(base, ldap_filter, attributes, **kwargs):
        return [
            {
                "dn": "CN=Service Account,OU=Users,DC=corp,DC=local",
                "attributes": {"objectClass": ("top", "user")},
                "raw_attributes": {"objectSid": [trustee]},
            }
        ]

    monkeypatch.setattr(collector, "_search", fake_search)
    memberships, unresolved, possible_groups = collector._target_group_memberships(
        "DC=corp,DC=local", (), {trustee}
    )
    assert memberships == {}
    assert unresolved == set()
    assert possible_groups == set()


def test_sysvol_failure_is_scoped_to_the_failed_policy_family(monkeypatch) -> None:
    impacket = ModuleType("impacket")
    impacket.__path__ = []
    smb_module = ModuleType("impacket.smbconnection")

    class FakeSmb:
        def __init__(self, *args, **kwargs):
            pass

        def login(self, *args, **kwargs):
            pass

        def getFile(self, share, path, callback):
            if path.endswith("gpt.ini"):
                callback(b"[General]\r\nVersion=7\r\n")
            elif path.endswith("GptTmpl.inf"):
                raise OSError("STATUS_NO_SUCH_FILE")
            else:
                raise PermissionError("Registry.pol access denied")

        def logoff(self):
            pass

    smb_module.SMBConnection = FakeSmb
    monkeypatch.setitem(sys.modules, "impacket", impacket)
    monkeypatch.setitem(sys.modules, "impacket.smbconnection", smb_module)
    gpo = GPO(
        dn="CN={AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA},CN=Policies,DC=corp,DC=local",
        guid="{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}",
        name="Scoped failure",
    )
    environment = Environment(
        soms={}, gpos={gpo.dn.casefold(): gpo}, principals=[], targets=[]
    )
    result = collect_sysvol(
        environment, CollectionConfig(domain="corp.local", dc_ip="10.0.0.1")
    )
    collected = result.gpo(gpo.dn)
    assert collected is not None
    assert collected.gpt_version == 7
    assert collected.settings_complete is False
    assert collected.incomplete_setting_kinds == (SettingKind.REGISTRY,)
    assert any("Registry.pol access denied" in reason for reason in collected.settings_uncertainty_reasons)


def _fake_ldap3(monkeypatch, captured: dict) -> None:
    module = ModuleType("ldap3")
    module.KERBEROS = "KERBEROS"
    module.ENCRYPT = "ENCRYPT"
    module.NONE = "NONE"
    module.NTLM = "NTLM"
    module.SASL = "SASL"
    module.SIMPLE = "SIMPLE"
    module.BASE = "BASE"
    module.SUBTREE = "SUBTREE"
    module.TLS_CHANNEL_BINDING = "TLS_CHANNEL_BINDING"

    def tls(**kwargs):
        captured["tls"] = kwargs
        return SimpleNamespace(**kwargs)

    def server(*args, **kwargs):
        captured["server"] = (args, kwargs)
        return SimpleNamespace()

    def connection(*args, **kwargs):
        captured["connection"] = (args, kwargs)
        return SimpleNamespace(
            socket=SimpleNamespace(getpeername=lambda: ("10.0.0.1", 636))
        )

    module.Tls = tls
    module.Server = server
    module.Connection = connection
    monkeypatch.setitem(sys.modules, "ldap3", module)


def test_ldaps_requires_certificate_validation_by_default(monkeypatch) -> None:
    captured: dict = {}
    _fake_ldap3(monkeypatch, captured)
    collector = object.__new__(LDAPCollector)
    collector.config = CollectionConfig(
        domain="corp.local",
        dc_ip="10.0.0.1",
        dc_host="dc01.corp.local",
        ldap_uri="ldaps://dc01.corp.local",
        ca_file="/tmp/corp-ca.pem",
    )
    collector.warnings = []
    collector.ldap_endpoint = None
    collector.ldap_peer_ip = None
    collector.tls_verified = None
    collector._connect()
    assert captured["tls"]["validate"] == ssl.CERT_REQUIRED
    assert captured["tls"]["ca_certs_file"] == "/tmp/corp-ca.pem"
    assert collector.tls_verified is True
    assert captured["server"][1]["connect_timeout"] == 10.0
    assert captured["connection"][1]["receive_timeout"] == 30.0
    assert captured["connection"][1]["auto_referrals"] is False
    assert captured["connection"][1]["read_only"] is True


def test_tls_no_verify_is_explicit_and_noisy(monkeypatch) -> None:
    captured: dict = {}
    _fake_ldap3(monkeypatch, captured)
    collector = object.__new__(LDAPCollector)
    collector.config = CollectionConfig(
        domain="corp.local",
        dc_ip="10.0.0.1",
        ldap_uri="ldaps://10.0.0.1",
        tls_no_verify=True,
    )
    collector.warnings = []
    collector.ldap_endpoint = None
    collector.ldap_peer_ip = None
    collector.tls_verified = None
    collector._connect()
    assert captured["tls"]["validate"] == ssl.CERT_NONE
    assert any("not authenticated" in warning for warning in collector.warnings)


def test_collection_limits_must_be_positive() -> None:
    with pytest.raises(ValueError, match="must be positive"):
        CollectionConfig(
            domain="corp.local", dc_ip="10.0.0.1", max_ldap_queries=0
        )


@pytest.mark.parametrize(
    ("uri", "expected_key", "expected_value"),
    (
        ("ldap://10.0.0.1", "session_security", "ENCRYPT"),
        ("ldaps://10.0.0.1", "channel_binding", "TLS_CHANNEL_BINDING"),
    ),
)
def test_ntlm_transport_security_is_enabled(
    monkeypatch, uri: str, expected_key: str, expected_value: str
) -> None:
    captured: dict = {}
    _fake_ldap3(monkeypatch, captured)
    collector = object.__new__(LDAPCollector)
    collector.config = CollectionConfig(
        domain="corp.local",
        dc_ip="10.0.0.1",
        ldap_uri=uri,
        auth=AuthConfig(
            username="auditor",
            password="secret",
            auth_domain="CORP",
        ),
    )
    collector.warnings = []
    collector.ldap_endpoint = None
    collector.ldap_peer_ip = None
    collector.tls_verified = None
    collector._connect()
    assert captured["connection"][1][expected_key] == expected_value


def test_ldap_search_retries_with_a_hard_query_budget(monkeypatch) -> None:
    captured: dict = {}
    _fake_ldap3(monkeypatch, captured)
    calls = 0

    def paged_search(**kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("transient LDAP failure")
        assert kwargs["paged_size"] == 123
        return iter(({"type": "searchResEntry", "dn": "DC=corp,DC=local"},))

    collector = object.__new__(LDAPCollector)
    collector.config = CollectionConfig(
        domain="corp.local",
        dc_ip="10.0.0.1",
        retry_limit=1,
        retry_backoff=0,
        ldap_page_size=123,
        max_ldap_queries=2,
    )
    collector._query_count = 0
    collector.connection = SimpleNamespace(
        extend=SimpleNamespace(
            standard=SimpleNamespace(paged_search=paged_search)
        )
    )
    entries = collector._search("", "(objectClass=*)", ["defaultNamingContext"])
    assert len(entries) == 1
    assert calls == 2
    with pytest.raises(RuntimeError, match="query budget exhausted"):
        collector._search("", "(objectClass=*)", [])


def test_ldap_uri_rejects_embedded_credentials(monkeypatch) -> None:
    captured: dict = {}
    _fake_ldap3(monkeypatch, captured)
    collector = object.__new__(LDAPCollector)
    collector.config = CollectionConfig(
        domain="corp.local",
        dc_ip="10.0.0.1",
        ldap_uri="ldaps://user:secret@10.0.0.1",
    )
    collector.warnings = []
    collector.ldap_endpoint = None
    collector.ldap_peer_ip = None
    collector.tls_verified = None
    with pytest.raises(RuntimeError, match="must not contain credentials"):
        collector._connect()
