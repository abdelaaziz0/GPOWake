from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from . import __version__
from .collectors import AuthConfig
from .models import AccessDecision, Environment, GPO, GptAccessProbe, Target
from .observations import (
    GPT_FILE_GENERIC_READ,
    OBSERVATION_SCHEMA_VERSION,
    SMB_ORACLE_NAME,
    expected_gpt_unc,
    gpo_matches,
    machine_credential_matches,
    target_matches,
    token_sids_sha256,
    unique_match,
)


@dataclass(frozen=True)
class SmbOracleConfig:
    dc_ip: str
    dc_host: str | None
    target_selector: str
    gpo_selectors: tuple[str, ...]
    auth: AuthConfig
    timeout: float = 30.0
    max_file_bytes: int = 64 * 1024 * 1024
    max_gpos: int = 5_000

    def __post_init__(self) -> None:
        if not self.dc_ip.strip():
            raise ValueError("SMB oracle requires --dc-ip")
        if not self.target_selector.strip():
            raise ValueError("SMB oracle requires one target selector")
        if min(self.timeout, self.max_file_bytes, self.max_gpos) <= 0:
            raise ValueError("SMB oracle limits must be positive")
        if not self.auth.username.strip():
            raise ValueError(
                "SMB oracle requires --username naming the target machine account"
            )
        if self.auth.kerberos:
            raise ValueError(
                "SMB oracle requires NTLM machine-account password/hash authentication; "
                "Kerberos cache identity cannot yet be independently attested"
            )


def _access_denied(exc: Exception) -> bool:
    try:
        if int(exc.getErrorCode()) == 0xC0000022:  # type: ignore[attr-defined]
            return True
    except (AttributeError, TypeError, ValueError):
        pass
    text = str(exc).upper()
    return "STATUS_ACCESS_DENIED" in text or "0XC0000022" in text


def _snapshot_smb_peer(environment: Environment) -> str:
    if not environment.smb_endpoint:
        raise ValueError("SMB oracle requires a snapshot with a pinned SMB endpoint")
    match = re.fullmatch(r"smb://[^ ]+ \(peer ([^)]+)\)", environment.smb_endpoint)
    if match is None:
        raise ValueError("snapshot SMB endpoint does not contain a pinned peer")
    return match.group(1)


def _login_name(username: str) -> str:
    return username.rsplit("\\", 1)[-1].split("@", 1)[0]


def _credential_principal(auth: AuthConfig) -> str:
    if "\\" in auth.username or "@" in auth.username or not auth.auth_domain:
        return auth.username
    return f"{auth.auth_domain}\\{auth.username}"


def _relative_path(value: str) -> str:
    path = value.replace("/", "\\")
    parts = path.split("\\")
    if path.startswith("\\") or ":" in path or any(
        part in {"", ".", ".."} for part in parts
    ):
        raise ValueError(f"snapshot contains unsafe GPT hash path {value!r}")
    return "\\".join(parts)


def _read_file(smb: Any, share: str, path: str, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0

    def append_chunk(chunk: bytes) -> None:
        nonlocal total
        total += len(chunk)
        if total > maximum:
            raise RuntimeError(f"SMB oracle file exceeds {maximum} bytes")
        chunks.append(bytes(chunk))

    smb.getFile(share, path, append_chunk)
    return b"".join(chunks)


def _selected_gpos(
    environment: Environment, selectors: Iterable[str]
) -> list[GPO]:
    gpos = list(environment.gpos.values())
    selected: list[GPO] = []
    for selector in selectors:
        gpo = unique_match(gpos, selector, gpo_matches, "GPO")
        if gpo not in selected:
            selected.append(gpo)
    return selected


def collect_smb_effective_observations(
    environment: Environment,
    *,
    snapshot_sha256: str,
    config: SmbOracleConfig,
) -> dict[str, object]:
    """Perform effective SMB reads as one target and return strict evidence JSON."""

    if environment.collected_at is None:
        raise ValueError("SMB oracle requires a live snapshot with collected_at")
    if not environment.source_dc:
        raise ValueError("SMB oracle requires a snapshot source_dc")
    snapshot_peer = _snapshot_smb_peer(environment)
    if config.dc_ip.casefold() != snapshot_peer.casefold():
        raise ValueError("--dc-ip does not match the snapshot SMB peer")
    if config.dc_host and config.dc_host.casefold() != environment.source_dc.casefold():
        raise ValueError("--dc-host does not match the snapshot source DC")
    try:
        collected = datetime.fromisoformat(
            environment.collected_at.replace("Z", "+00:00")
        ).astimezone(timezone.utc)
    except ValueError as exc:
        raise ValueError("snapshot collected_at is not an ISO-8601 timestamp") from exc
    if abs(datetime.now(timezone.utc) - collected).total_seconds() > 30 * 60:
        raise ValueError(
            "snapshot is more than 30 minutes old; recollect it before running the oracle"
        )
    target = unique_match(
        list(environment.targets),
        config.target_selector,
        target_matches,
        "target",
    )
    credential_principal = _credential_principal(config.auth)
    if not machine_credential_matches(target, credential_principal):
        raise ValueError(
            "--username must name the selected target machine account "
            f"({target.name.split('.', 1)[0]}$)"
        )
    gpos = _selected_gpos(environment, config.gpo_selectors)
    if not gpos:
        raise ValueError("SMB oracle requires at least one selected GPO")
    if len(gpos) > config.max_gpos:
        raise ValueError(
            f"SMB oracle selection exceeds the {config.max_gpos} GPO budget"
        )
    for gpo in gpos:
        if gpo.version_number is None or gpo.gpt_version is None:
            raise ValueError(f"{gpo.name}: snapshot lacks AD/GPT version binding")
        if not gpo.gpt_hashes:
            raise ValueError(f"{gpo.name}: snapshot lacks GPT file hashes")

    try:
        from impacket.smbconnection import SMBConnection  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - optional extra
        raise RuntimeError(
            "SMB GPT oracle requires the 'collect' extra (impacket)"
        ) from exc

    remote_name = environment.source_dc
    smb = SMBConnection(remote_name, config.dc_ip, timeout=config.timeout)
    auth = config.auth
    try:
        smb.login(
            _login_name(auth.username),
            auth.password,
            auth.auth_domain,
            auth.lmhash,
            auth.nthash,
        )
        try:
            guest_session = bool(smb.isGuestSession())
        except AttributeError as exc:
            raise RuntimeError(
                "SMB library cannot attest whether the oracle session is guest"
            ) from exc
        if guest_session:
            raise RuntimeError("SMB oracle refused an authenticated guest session")

        observed_at = datetime.now(timezone.utc).isoformat()
        observations: list[dict[str, object]] = []
        for gpo in gpos:
            unc = expected_gpt_unc(environment.source_dc, gpo)
            unc_parts = [part for part in unc.split("\\") if part]
            share = unc_parts[1]
            root = "\\".join(unc_parts[2:])
            probes: list[GptAccessProbe] = []
            decision = AccessDecision.ALLOW
            for relative, expected_hash in gpo.gpt_hashes:
                safe_relative = _relative_path(relative)
                try:
                    data = _read_file(
                        smb,
                        share,
                        f"{root}\\{safe_relative}",
                        config.max_file_bytes,
                    )
                except Exception as exc:
                    if not _access_denied(exc):
                        raise RuntimeError(
                            f"{gpo.name}: SMB probe failed for {safe_relative}: {exc}"
                        ) from exc
                    probes.append(GptAccessProbe(safe_relative, "ACCESS_DENIED"))
                    decision = AccessDecision.DENY
                    break
                actual_hash = hashlib.sha256(data).hexdigest()
                if actual_hash.casefold() != expected_hash.casefold():
                    raise RuntimeError(
                        f"{gpo.name}: {safe_relative} changed since snapshot collection"
                    )
                probes.append(GptAccessProbe(safe_relative, "READ_OK", actual_hash))
            observations.append(
                {
                    "target": target.sid,
                    "gpo": gpo.dn,
                    "decision": decision.value,
                    "source": "SMB_EFFECTIVE_IO",
                    "oracle": SMB_ORACLE_NAME,
                    "oracle_version": __version__,
                    "observed_at": observed_at,
                    "desired_access": GPT_FILE_GENERIC_READ,
                    "gpt_unc_path": unc,
                    "dc": environment.source_dc,
                    "target_sid": target.sid,
                    "token_sids_sha256": token_sids_sha256(target),
                    "credential_principal": credential_principal,
                    "gpo_ad_version": gpo.version_number,
                    "gpt_version": gpo.gpt_version,
                    "share_sd_sha256": None,
                    "ntfs_sd_sha256": None,
                    "probes": [asdict(probe) for probe in probes],
                }
            )
        return {
            "schema_version": OBSERVATION_SCHEMA_VERSION,
            "snapshot_sha256": snapshot_sha256,
            "observations": observations,
        }
    finally:
        try:
            smb.logoff()
        except Exception:
            pass
