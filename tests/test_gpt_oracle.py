from __future__ import annotations

import hashlib
import json
import sys
import types
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from gpowake.collectors import AuthConfig
from gpowake.gpt_oracle import (
    SmbOracleConfig,
    _attest_machine_sid,
    collect_smb_effective_observations,
)
from gpowake.models import AccessDecision, Link
from gpowake.observations import GPT_FILE_GENERIC_READ, import_gpt_access_observations
from gpowake.snapshot import save_snapshot

from conftest import DANGEROUS_DN, environment


def _live_hashed_environment(data: bytes):
    env = environment(
        ou_links=(Link(DANGEROUS_DN, 0, 1),),
        include_safe=False,
    )
    env.collected_at = datetime.now(timezone.utc).isoformat()
    env.source_dc = "dc01.corp.local"
    env.smb_endpoint = "smb://dc01.corp.local (peer 192.0.2.10)"
    gpo = env.gpo(DANGEROUS_DN)
    assert gpo is not None
    env.gpos[gpo.dn.casefold()] = replace(
        gpo,
        file_sys_path=(
            f"\\\\dc01.corp.local\\SYSVOL\\corp.local\\Policies\\{gpo.guid}"
        ),
        functionality_version=2,
        version_number=7,
        gpt_version=7,
        gpt_hashes=(("gpt.ini", hashlib.sha256(data).hexdigest()),),
        gpt_file_sizes=(("gpt.ini", len(data)),),
    )
    return env


def _install_fake_smb(monkeypatch, smb_class) -> None:
    package = types.ModuleType("impacket")
    package.__path__ = []  # type: ignore[attr-defined]
    module = types.ModuleType("impacket.smbconnection")
    module.SMBConnection = smb_class
    monkeypatch.setitem(sys.modules, "impacket", package)
    monkeypatch.setitem(sys.modules, "impacket.smbconnection", module)
    monkeypatch.setattr(
        "gpowake.gpt_oracle._attest_machine_sid",
        lambda _environment, target, _config: target.sid,
    )


def _config(gpo_dn: str) -> SmbOracleConfig:
    return SmbOracleConfig(
        dc_ip="192.0.2.10",
        dc_host="dc01.corp.local",
        target_selector="SRV1",
        gpo_selectors=(gpo_dn,),
        auth=AuthConfig(
            username="SRV1$",
            password="secret",
            auth_domain="CORP",
        ),
    )


def test_smb_oracle_reads_and_hash_binds_every_snapshot_file(
    tmp_path, monkeypatch
) -> None:
    data = b"[General]\r\nVersion=7\r\n"
    env = _live_hashed_environment(data)
    snapshot = tmp_path / "snapshot.json"
    evidence = tmp_path / "evidence.json"
    save_snapshot(env, snapshot)
    snapshot_digest = hashlib.sha256(snapshot.read_bytes()).hexdigest()

    class FakeSmb:
        def __init__(self, remote_name, remote_host, timeout):
            assert (remote_name, remote_host) == ("dc01.corp.local", "192.0.2.10")

        def login(self, username, password, domain, lmhash, nthash):
            assert (username, password, domain) == ("SRV1$", "secret", "CORP")

        def connectTree(self, share):
            assert share == "SYSVOL"
            return 7

        def openFile(self, tree_id, path, *, desiredAccess):
            assert tree_id == 7
            assert path.endswith("\\gpt.ini")
            assert desiredAccess == GPT_FILE_GENERIC_READ
            return 11

        def readFile(self, tree_id, file_id, *, offset, bytesToRead, singleCall):
            assert (tree_id, file_id, singleCall) == (7, 11, True)
            return data if offset == 0 else b""

        def closeFile(self, tree_id, file_id):
            assert (tree_id, file_id) == (7, 11)

        def isGuestSession(self):
            return 0

        def logoff(self):
            return None

    _install_fake_smb(monkeypatch, FakeSmb)
    document = collect_smb_effective_observations(
        env,
        snapshot_sha256=snapshot_digest,
        config=_config(DANGEROUS_DN),
    )
    row = document["observations"][0]
    assert row["decision"] == "ALLOW"
    assert row["probes"] == [
        {
            "relative_path": "gpt.ini",
            "status": "READ_OK",
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }
    ]
    evidence.write_text(json.dumps(document))
    assert (
        import_gpt_access_observations(
            env, evidence, snapshot_sha256=snapshot_digest
        )
        == 1
    )
    assert env.targets[0].gpt_read_decision_for(env.gpo(DANGEROUS_DN)) is AccessDecision.ALLOW


def test_smb_oracle_records_only_real_access_denials(monkeypatch) -> None:
    data = b"gpt"
    env = _live_hashed_environment(data)

    class AccessDenied(Exception):
        def getErrorCode(self):
            return 0xC0000022

    class FakeSmb:
        def __init__(self, remote_name, remote_host, timeout):
            pass

        def login(self, username, password, domain, lmhash, nthash):
            pass

        def connectTree(self, share):
            return 7

        def openFile(self, tree_id, path, *, desiredAccess):
            raise AccessDenied("STATUS_ACCESS_DENIED")

        def isGuestSession(self):
            return 0

        def logoff(self):
            pass

    _install_fake_smb(monkeypatch, FakeSmb)
    document = collect_smb_effective_observations(
        env,
        snapshot_sha256="a" * 64,
        config=_config(DANGEROUS_DN),
    )
    row = document["observations"][0]
    assert row["decision"] == "DENY"
    assert row["probes"][0]["status"] == "ACCESS_DENIED"


def test_smb_oracle_does_not_turn_transport_failure_into_deny(monkeypatch) -> None:
    env = _live_hashed_environment(b"gpt")

    class FakeSmb:
        def __init__(self, remote_name, remote_host, timeout):
            pass

        def login(self, username, password, domain, lmhash, nthash):
            pass

        def connectTree(self, share):
            return 7

        def openFile(self, tree_id, path, *, desiredAccess):
            raise TimeoutError("socket timed out")

        def isGuestSession(self):
            return 0

        def logoff(self):
            pass

    _install_fake_smb(monkeypatch, FakeSmb)
    with pytest.raises(RuntimeError, match="SMB probe failed"):
        collect_smb_effective_observations(
            env,
            snapshot_sha256="a" * 64,
            config=_config(DANGEROUS_DN),
        )


def test_smb_oracle_rejects_guest_session(monkeypatch) -> None:
    env = _live_hashed_environment(b"gpt")

    class FakeSmb:
        def __init__(self, remote_name, remote_host, timeout):
            pass

        def login(self, username, password, domain, lmhash, nthash):
            pass

        def isGuestSession(self):
            return 1

        def logoff(self):
            pass

    _install_fake_smb(monkeypatch, FakeSmb)
    with pytest.raises(RuntimeError, match="guest session"):
        collect_smb_effective_observations(
            env,
            snapshot_sha256="a" * 64,
            config=_config(DANGEROUS_DN),
        )


def test_smb_oracle_rejects_unattested_kerberos_identity() -> None:
    with pytest.raises(ValueError, match="Kerberos cache identity"):
        SmbOracleConfig(
            dc_ip="192.0.2.10",
            dc_host="dc01.corp.local",
            target_selector="SRV1",
            gpo_selectors=(DANGEROUS_DN,),
            auth=AuthConfig(username="SRV1$", kerberos=True),
        )


def test_smb_oracle_continues_after_one_file_family_is_denied(monkeypatch) -> None:
    files = {
        "gpt.ini": b"root",
        "Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf": b"security",
        "Machine\\Registry.pol": b"registry",
    }
    env = _live_hashed_environment(files["gpt.ini"])
    gpo = env.gpo(DANGEROUS_DN)
    assert gpo is not None
    env.gpos[gpo.dn.casefold()] = replace(
        gpo,
        gpt_hashes=tuple(
            (path, hashlib.sha256(data).hexdigest())
            for path, data in files.items()
        ),
        gpt_file_sizes=tuple((path, len(data)) for path, data in files.items()),
    )

    class AccessDenied(Exception):
        def getErrorCode(self):
            return 0xC0000022

    class FakeSmb:
        def __init__(self, remote_name, remote_host, timeout):
            self.paths = {}

        def login(self, username, password, domain, lmhash, nthash):
            pass

        def isGuestSession(self):
            return 0

        def connectTree(self, share):
            return 4

        def openFile(self, tree_id, path, *, desiredAccess):
            assert desiredAccess == GPT_FILE_GENERIC_READ
            relative = next(item for item in files if path.endswith(item))
            if relative == "Machine\\Registry.pol":
                raise AccessDenied("STATUS_ACCESS_DENIED")
            handle = len(self.paths) + 1
            self.paths[handle] = relative
            return handle

        def readFile(self, tree_id, file_id, *, offset, bytesToRead, singleCall):
            data = files[self.paths[file_id]]
            return data if offset == 0 else b""

        def closeFile(self, tree_id, file_id):
            pass

        def logoff(self):
            pass

    _install_fake_smb(monkeypatch, FakeSmb)
    document = collect_smb_effective_observations(
        env,
        snapshot_sha256="a" * 64,
        config=_config(DANGEROUS_DN),
    )
    row = document["observations"][0]
    assert row["decision"] == "UNKNOWN"
    assert [probe["status"] for probe in row["probes"]] == [
        "READ_OK",
        "READ_OK",
        "ACCESS_DENIED",
    ]
    assert document["preflight"]["total_bytes"] == sum(map(len, files.values()))


def test_smb_oracle_preflight_rejects_aggregate_byte_budget(monkeypatch) -> None:
    env = _live_hashed_environment(b"three")
    monkeypatch.setattr(
        "gpowake.gpt_oracle._attest_machine_sid",
        lambda *_args: pytest.fail("identity/network work ran before preflight"),
    )
    with pytest.raises(ValueError, match="preflight exceeds"):
        collect_smb_effective_observations(
            env,
            snapshot_sha256="a" * 64,
            config=replace(_config(DANGEROUS_DN), max_total_bytes=4),
        )


def test_pinned_ldap_bind_attests_exact_machine_sid(monkeypatch) -> None:
    env = _live_hashed_environment(b"gpt")
    target = replace(
        env.targets[0],
        name="srv1.corp.local",
        token_sids=(*env.targets[0].token_sids, "S-1-1-0", "S-1-5-11"),
    )
    closed = []

    class FakeValue:
        def __init__(self, value):
            self.value = value

        def asOctets(self):
            return self.value

    class FakeSearchResultEntry(dict):
        pass

    implicit = {target.sid.casefold(), "s-1-1-0", "s-1-5-11"}
    group_sids = sorted(
        sid for sid in target.all_sids if sid.casefold() not in implicit
    )
    encoded_groups = {
        f"group-{index}".encode(): sid for index, sid in enumerate(group_sids)
    }
    entry = FakeSearchResultEntry(
        attributes=[
            {"type": "sAMAccountName", "vals": [FakeValue(b"SRV1$")]},
            {"type": "objectSid", "vals": [FakeValue(b"binary-sid")]},
            {
                "type": "dNSHostName",
                "vals": [FakeValue(b"srv1.corp.local")],
            },
            {
                "type": "tokenGroups",
                "vals": [FakeValue(value) for value in encoded_groups],
            },
        ]
    )

    class FakeConnection:
        def __init__(self, url, base_dn, destination_ip, signing):
            assert url == "ldap://dc01.corp.local"
            assert base_dn == "DC=corp,DC=local"
            assert destination_ip == "192.0.2.10"
            assert signing is True

        def login(self, username, password, domain, lmhash, nthash):
            assert (username, password, domain) == ("SRV1$", "secret", "CORP")

        def search(self, **kwargs):
            assert kwargs["searchBase"] == target.dn
            assert kwargs["searchFilter"] == "(objectClass=computer)"
            assert "tokenGroups" in kwargs["attributes"]
            assert "sIDHistory" in kwargs["attributes"]
            return [entry]

        def close(self):
            closed.append(True)

    class FakeSid:
        def __init__(self, data):
            self.data = data

        def formatCanonical(self):
            if self.data == b"binary-sid":
                return target.sid
            return encoded_groups[self.data]

    package = types.ModuleType("impacket")
    package.__path__ = []  # type: ignore[attr-defined]
    ldap_package = types.ModuleType("impacket.ldap")
    ldap_package.__path__ = []  # type: ignore[attr-defined]
    ldap_module = types.ModuleType("impacket.ldap.ldap")
    ldap_module.LDAPConnection = FakeConnection
    asn1_module = types.ModuleType("impacket.ldap.ldapasn1")
    asn1_module.Scope = lambda value: value
    asn1_module.SearchResultEntry = FakeSearchResultEntry
    types_module = types.ModuleType("impacket.ldap.ldaptypes")
    types_module.LDAP_SID = FakeSid
    ldap_package.ldap = ldap_module
    monkeypatch.setitem(sys.modules, "impacket", package)
    monkeypatch.setitem(sys.modules, "impacket.ldap", ldap_package)
    monkeypatch.setitem(sys.modules, "impacket.ldap.ldap", ldap_module)
    monkeypatch.setitem(sys.modules, "impacket.ldap.ldapasn1", asn1_module)
    monkeypatch.setitem(sys.modules, "impacket.ldap.ldaptypes", types_module)

    assert _attest_machine_sid(env, target, _config(DANGEROUS_DN)) == target.sid
    assert closed == [True]
