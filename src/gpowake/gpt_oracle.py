from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from . import __version__
from .collectors import AuthConfig
from .models import (
    AccessDecision,
    Environment,
    GPO,
    GptAccessProbe,
    Target,
    normalize_sid,
)
from .observations import (
    GPT_FILE_GENERIC_READ,
    OBSERVATION_SCHEMA_VERSION,
    SMB_ORACLE_NAME,
    SMB_IDENTITY_ATTESTATION,
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
    max_total_bytes: int = 512 * 1024 * 1024
    max_total_files: int = 10_000
    max_total_probes: int = 10_000

    def __post_init__(self) -> None:
        if not self.dc_ip.strip():
            raise ValueError("SMB oracle requires --dc-ip")
        if not self.target_selector.strip():
            raise ValueError("SMB oracle requires one target selector")
        if min(
            self.timeout,
            self.max_file_bytes,
            self.max_gpos,
            self.max_total_bytes,
            self.max_total_files,
            self.max_total_probes,
        ) <= 0:
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
        if int(exc.getErrorCode()) == 0xC0000022:
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


def _credential_principal(target: Target, auth: AuthConfig) -> str:
    if not target.sam_account_name or not target.netbios_domain:
        raise ValueError("snapshot target lacks LDAP-collected machine identity fields")
    if auth.auth_domain.casefold() != target.netbios_domain.casefold():
        raise ValueError("--auth-domain does not match the target's LDAP domain")
    supplied = (
        auth.username
        if "\\" in auth.username or "@" in auth.username
        else f"{auth.auth_domain}\\{auth.username}"
    )
    if not machine_credential_matches(target, supplied):
        raise ValueError("the supplied canonical domain/account does not match the target")
    return f"{target.netbios_domain}\\{target.sam_account_name}"


def _relative_path(value: str) -> str:
    path = value.replace("/", "\\")
    parts = path.split("\\")
    if path.startswith("\\") or ":" in path or any(
        part in {"", ".", ".."} for part in parts
    ):
        raise ValueError(f"snapshot contains unsafe GPT hash path {value!r}")
    return "\\".join(parts)


@dataclass
class _OracleBudget:
    config: SmbOracleConfig
    bytes_read: int = 0
    files: int = 0
    probes: int = 0

    def start_probe(self) -> None:
        self.probes += 1
        self.files += 1
        if self.probes > self.config.max_total_probes:
            raise RuntimeError("SMB oracle aggregate probe budget exceeded")
        if self.files > self.config.max_total_files:
            raise RuntimeError("SMB oracle aggregate file budget exceeded")

    def add_bytes(self, count: int) -> None:
        self.bytes_read += count
        if self.bytes_read > self.config.max_total_bytes:
            raise RuntimeError("SMB oracle aggregate byte budget exceeded")


def _read_file_hash(
    smb: Any,
    tree_id: Any,
    path: str,
    expected_size: int,
    budget: _OracleBudget,
) -> tuple[str, int]:
    budget.start_probe()
    file_id = smb.openFile(
        tree_id,
        path,
        desiredAccess=GPT_FILE_GENERIC_READ,
    )
    hasher = hashlib.sha256()
    total = 0
    try:
        while True:
            remaining_file = budget.config.max_file_bytes - total
            remaining_total = budget.config.max_total_bytes - budget.bytes_read
            if min(remaining_file, remaining_total) < 0:
                raise RuntimeError("SMB oracle byte budget exceeded")
            requested = min(1024 * 1024, remaining_file + 1, remaining_total + 1)
            chunk = smb.readFile(
                tree_id,
                file_id,
                offset=total,
                bytesToRead=requested,
                singleCall=True,
            )
            if not chunk:
                break
            data = bytes(chunk)
            total += len(data)
            budget.add_bytes(len(data))
            if total > budget.config.max_file_bytes:
                raise RuntimeError(
                    f"SMB oracle file exceeds {budget.config.max_file_bytes} bytes"
                )
            hasher.update(data)
    except Exception:
        try:
            smb.closeFile(tree_id, file_id)
        except Exception:
            pass
        raise
    smb.closeFile(tree_id, file_id)
    if total != expected_size:
        raise RuntimeError(
            f"SMB oracle file size changed from {expected_size} to {total} bytes"
        )
    return hasher.hexdigest(), total


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


def _attest_machine_sid(
    environment: Environment,
    target: Target,
    config: SmbOracleConfig,
) -> str:
    """Attest the exact machine object and authorization token on the pinned DC."""

    if not target.dns_domain or not target.sam_account_name or not target.netbios_domain:
        raise ValueError("snapshot target lacks exact LDAP machine identity fields")
    if target.token_incomplete or target.unresolved_sids:
        raise ValueError("snapshot target token is incomplete and cannot be attested")
    try:
        from impacket.ldap import ldap
        from impacket.ldap.ldapasn1 import (
            Scope,
            SearchResultEntry,
        )
        from impacket.ldap.ldaptypes import LDAP_SID
    except ImportError as exc:
        raise RuntimeError(
            "SMB GPT oracle identity attestation requires the 'collect' extra"
        ) from exc

    base_dn = ",".join(f"DC={label}" for label in target.dns_domain.split("."))
    connection = ldap.LDAPConnection(
        f"ldap://{environment.source_dc}",
        base_dn,
        config.dc_ip,
        signing=True,
    )
    try:
        auth = config.auth
        connection.login(
            target.sam_account_name,
            auth.password,
            target.netbios_domain,
            auth.lmhash,
            auth.nthash,
        )
        rows = connection.search(
            searchBase=target.dn,
            scope=Scope("baseObject"),
            sizeLimit=1,
            timeLimit=max(1, int(config.timeout)),
            searchFilter="(objectClass=computer)",
            attributes=[
                "objectSid",
                "sAMAccountName",
                "dNSHostName",
                "sIDHistory",
                "tokenGroups",
            ],
        )
        entries = [row for row in rows if isinstance(row, SearchResultEntry)]
        if len(entries) != 1:
            raise RuntimeError("pinned LDAP attestation did not return the target object")
        attributes: dict[str, list[bytes]] = {}
        for attribute in entries[0]["attributes"]:
            values = attribute["vals"]
            attributes[str(attribute["type"]).casefold()] = [
                value.asOctets() for value in values
            ]
        sam_values = attributes.get("samaccountname", [])
        sam = (sam_values[0] if sam_values else b"").decode(
            "utf-8", errors="strict"
        )
        if sam.casefold() != target.sam_account_name.casefold():
            raise RuntimeError("pinned LDAP sAMAccountName does not match the snapshot")
        object_sid_values = attributes.get("objectsid", [])
        if len(object_sid_values) != 1:
            raise RuntimeError("pinned LDAP target object did not return objectSid")
        sid = LDAP_SID(data=object_sid_values[0]).formatCanonical()
        if sid.casefold() != target.sid.casefold():
            raise RuntimeError("pinned LDAP object SID does not match the snapshot target")
        dns_values = attributes.get("dnshostname", [])
        dns_name = (dns_values[0] if dns_values else b"").decode(
            "utf-8", errors="strict"
        )
        if "." in target.name and dns_name.casefold() != target.name.casefold():
            raise RuntimeError("pinned LDAP dNSHostName does not match the snapshot")
        attested_token = {
            normalize_sid("S-1-1-0"),
            normalize_sid("S-1-5-11"),
            normalize_sid(sid),
        }
        for name in ("sidhistory", "tokengroups"):
            for raw_group_sid in attributes.get(name, []):
                attested_token.add(
                    normalize_sid(LDAP_SID(data=raw_group_sid).formatCanonical())
                )
        if frozenset(attested_token) != target.all_sids:
            raise RuntimeError(
                "pinned LDAP tokenGroups/sIDHistory do not match the snapshot token"
            )
        return sid
    finally:
        connection.close()


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
    credential_principal = _credential_principal(target, config.auth)
    gpos = _selected_gpos(environment, config.gpo_selectors)
    if not gpos:
        raise ValueError("SMB oracle requires at least one selected GPO")
    if len(gpos) > config.max_gpos:
        raise ValueError(
            f"SMB oracle selection exceeds the {config.max_gpos} GPO budget"
        )
    planned_files = 0
    planned_bytes = 0
    for gpo in gpos:
        if gpo.version_number is None or gpo.gpt_version is None:
            raise ValueError(f"{gpo.name}: snapshot lacks AD/GPT version binding")
        if not gpo.gpt_hashes:
            raise ValueError(f"{gpo.name}: snapshot lacks GPT file hashes")
        sizes = {
            path.replace("/", "\\").casefold(): size
            for path, size in gpo.gpt_file_sizes
        }
        hashes = {
            path.replace("/", "\\").casefold() for path, _digest in gpo.gpt_hashes
        }
        if set(sizes) != hashes:
            raise ValueError(f"{gpo.name}: snapshot lacks exact GPT file sizes")
        if any(size > config.max_file_bytes for size in sizes.values()):
            raise ValueError(
                f"{gpo.name}: a GPT file exceeds the per-file oracle budget"
            )
        planned_files += len(sizes)
        planned_bytes += sum(sizes.values())
    if planned_files > config.max_total_files:
        raise ValueError(
            f"SMB oracle preflight exceeds the {config.max_total_files} file budget"
        )
    if planned_files > config.max_total_probes:
        raise ValueError(
            f"SMB oracle preflight exceeds the {config.max_total_probes} probe budget"
        )
    if planned_bytes > config.max_total_bytes:
        raise ValueError(
            f"SMB oracle preflight exceeds the {config.max_total_bytes}-byte budget"
        )

    try:
        from impacket.smbconnection import SMBConnection
    except ImportError as exc:
        raise RuntimeError(
            "SMB GPT oracle requires the 'collect' extra (impacket)"
        ) from exc

    authenticated_sid = _attest_machine_sid(environment, target, config)
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

        tree_id = smb.connectTree("SYSVOL")
        budget = _OracleBudget(config)
        observed_at = datetime.now(timezone.utc).isoformat()
        observations: list[dict[str, object]] = []
        for gpo in gpos:
            unc = expected_gpt_unc(environment.source_dc, gpo)
            unc_parts = [part for part in unc.split("\\") if part]
            share = unc_parts[1]
            if share.casefold() != "sysvol":
                raise ValueError(f"{gpo.name}: GPT UNC is not on SYSVOL")
            root = "\\".join(unc_parts[2:])
            probes: list[GptAccessProbe] = []
            sizes = {
                path.replace("/", "\\").casefold(): size
                for path, size in gpo.gpt_file_sizes
            }
            for relative, expected_hash in gpo.gpt_hashes:
                safe_relative = _relative_path(relative)
                try:
                    actual_hash, actual_size = _read_file_hash(
                        smb,
                        tree_id,
                        f"{root}\\{safe_relative}",
                        sizes[safe_relative.casefold()],
                        budget,
                    )
                except Exception as exc:
                    if not _access_denied(exc):
                        raise RuntimeError(
                            f"{gpo.name}: SMB probe failed for {safe_relative}: {exc}"
                        ) from exc
                    probes.append(GptAccessProbe(safe_relative, "ACCESS_DENIED"))
                    continue
                if actual_hash.casefold() != expected_hash.casefold():
                    raise RuntimeError(
                        f"{gpo.name}: {safe_relative} changed since snapshot collection"
                    )
                probes.append(
                    GptAccessProbe(
                        safe_relative,
                        "READ_OK",
                        actual_hash,
                        actual_size,
                    )
                )
            root_probe = next(
                (
                    probe
                    for probe in probes
                    if probe.relative_path.casefold() == "gpt.ini"
                ),
                None,
            )
            if root_probe is None:
                raise RuntimeError(f"{gpo.name}: gpt.ini was not probed")
            decision = (
                AccessDecision.DENY
                if root_probe.status == "ACCESS_DENIED"
                else AccessDecision.ALLOW
                if all(probe.status == "READ_OK" for probe in probes)
                else AccessDecision.UNKNOWN
            )
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
                    "authenticated_sid": authenticated_sid,
                    "identity_attestation": SMB_IDENTITY_ATTESTATION,
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
            "preflight": {
                "selected_gpos": len(gpos),
                "total_files": planned_files,
                "total_probes": planned_files,
                "total_bytes": planned_bytes,
                "max_total_files": config.max_total_files,
                "max_total_probes": config.max_total_probes,
                "max_total_bytes": config.max_total_bytes,
            },
            "observations": observations,
        }
    finally:
        try:
            smb.logoff()
        except Exception:
            pass
