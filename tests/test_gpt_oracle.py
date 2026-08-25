from __future__ import annotations

import hashlib
import json
import sys
import types
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from gpowake.collectors import AuthConfig
from gpowake.gpt_oracle import SmbOracleConfig, collect_smb_effective_observations
from gpowake.models import AccessDecision, Link
from gpowake.observations import import_gpt_access_observations
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
    )
    return env


def _install_fake_smb(monkeypatch, smb_class) -> None:
    package = types.ModuleType("impacket")
    package.__path__ = []  # type: ignore[attr-defined]
    module = types.ModuleType("impacket.smbconnection")
    module.SMBConnection = smb_class
    monkeypatch.setitem(sys.modules, "impacket", package)
    monkeypatch.setitem(sys.modules, "impacket.smbconnection", module)


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

        def getFile(self, share, path, callback):
            assert share == "SYSVOL"
            assert path.endswith("\\gpt.ini")
            callback(data)

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

        def getFile(self, share, path, callback):
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

        def getFile(self, share, path, callback):
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
