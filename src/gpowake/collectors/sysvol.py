from __future__ import annotations

import configparser
import hashlib
import io
from dataclasses import replace

from ..models import Environment, SettingKind
from ..parsers.gpttmpl import parse_gpttmpl
from ..parsers.registry_pol import parse_registry_pol
from .ldap import CollectionConfig


class SysvolBudgetExceeded(RuntimeError):
    pass


_MISSING_POLICY_NTSTATUS = frozenset(
    {
        0xC000000F,
        0xC0000034,
        0xC000003A,
    }
)


def _is_missing_policy_file_error(exc: Exception) -> bool:
    """Recognize an optional GPT file or parent directory that does not exist."""

    get_error_code = getattr(exc, "getErrorCode", None)
    if callable(get_error_code):
        try:
            if int(get_error_code()) & 0xFFFFFFFF in _MISSING_POLICY_NTSTATUS:
                return True
        except (TypeError, ValueError):
            pass
    message = str(exc).upper()
    return any(
        status in message
        for status in (
            "STATUS_NO_SUCH_FILE",
            "STATUS_OBJECT_NAME_NOT_FOUND",
            "STATUS_OBJECT_PATH_NOT_FOUND",
        )
    )


def _unc_parts(unc: str) -> tuple[str, str]:
    parts = [part for part in unc.replace("/", "\\").split("\\") if part]
    if len(parts) < 3:
        raise ValueError(f"invalid gPCFileSysPath {unc!r}")
    return parts[1], "\\".join(parts[2:])


def _gpt_version(data: bytes) -> int | None:
    for encoding, errors in (("utf-8-sig", "strict"), ("cp1252", "replace")):
        try:
            text = data.decode(encoding, errors=errors)
            parser = configparser.ConfigParser()
            parser.read_file(io.StringIO(text))
            return parser.getint("General", "Version")
        except (UnicodeDecodeError, configparser.Error, ValueError):
            continue
    return None


def _validated_gpt_location(
    unc: str, config: CollectionConfig, guid: str
) -> tuple[str, str]:
    share, root = _unc_parts(unc)
    root_parts = [part for part in root.replace("/", "\\").split("\\") if part]
    if share.casefold() != "sysvol":
        raise ValueError("gPCFileSysPath does not reference the SYSVOL share")
    if len(root_parts) != 3:
        raise ValueError("gPCFileSysPath is not a GPO root")
    if root_parts[0].casefold() != config.domain.casefold():
        raise ValueError("gPCFileSysPath domain does not match the collected domain")
    if root_parts[1].casefold() != "policies":
        raise ValueError("gPCFileSysPath is outside SYSVOL Policies")
    if root_parts[2].strip("{}").casefold() != guid.strip("{}").casefold():
        raise ValueError("gPCFileSysPath GUID does not match the GPO")
    return share, "\\".join(root_parts)


def collect_sysvol(environment: Environment, config: CollectionConfig) -> Environment:
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError as exc:
        raise RuntimeError(
            "SYSVOL collection requires the 'collect' extra (impacket)"
        ) from exc

    remote_name = config.dc_host or config.domain
    environment.smb_endpoint = f"smb://{remote_name} (peer {config.dc_ip})"
    smb = SMBConnection(remote_name, config.dc_ip, timeout=config.smb_timeout)
    auth = config.auth
    if auth.kerberos:
        smb.kerberosLogin(
            auth.username,
            auth.password,
            config.domain.upper(),
            auth.lmhash,
            auth.nthash,
            kdcHost=config.dc_ip,
            useCache=True,
        )
    else:
        smb.login(
            auth.username, auth.password, auth.auth_domain, auth.lmhash, auth.nthash
        )

    if len(environment.gpos) * 3 > config.max_sysvol_probes:
        raise SysvolBudgetExceeded(
            "SYSVOL preflight exceeds the aggregate probe budget; narrow collection "
            "or raise --max-sysvol-probes"
        )
    aggregate_bytes = 0
    aggregate_files = 0
    aggregate_probes = 0

    def read_file(share: str, path: str) -> tuple[bytes, str]:
        nonlocal aggregate_bytes, aggregate_files, aggregate_probes
        aggregate_probes += 1
        if aggregate_probes > config.max_sysvol_probes:
            raise SysvolBudgetExceeded("SYSVOL aggregate probe budget exceeded")
        chunks: list[bytes] = []
        total = 0
        hasher = hashlib.sha256()

        def append_chunk(chunk: bytes) -> None:
            nonlocal aggregate_bytes, total
            total += len(chunk)
            aggregate_bytes += len(chunk)
            if total > config.max_sysvol_file_bytes:
                raise SysvolBudgetExceeded(
                    f"SYSVOL file exceeds {config.max_sysvol_file_bytes} bytes"
                )
            if aggregate_bytes > config.max_sysvol_total_bytes:
                raise SysvolBudgetExceeded("SYSVOL aggregate byte budget exceeded")
            data = bytes(chunk)
            hasher.update(data)
            chunks.append(data)

        smb.getFile(share, path, append_chunk)
        aggregate_files += 1
        if aggregate_files > config.max_sysvol_files:
            raise SysvolBudgetExceeded("SYSVOL aggregate file budget exceeded")
        return b"".join(chunks), hasher.hexdigest()

    for key, original in list(environment.gpos.items()):
        unc = original.file_sys_path or (
            f"\\\\{config.domain}\\SYSVOL\\{config.domain}\\Policies\\{original.guid}"
        )
        try:
            share, root = _validated_gpt_location(unc, config, original.guid)
            gpt_data, gpt_hash = read_file(share, root + "\\gpt.ini")
        except SysvolBudgetExceeded:
            raise
        except Exception as exc:
            environment.warnings.append(
                f"{original.name}: cannot read GPT from {unc}: {exc}"
            )
            environment.gpos[key] = replace(
                original,
                collector_gpt_readable=False,
                settings_complete=False,
                settings_uncertainty_reasons=(f"GPT collection failed: {exc}",),
                incomplete_setting_kinds=tuple(SettingKind),
            )
            continue
        settings = list(original.settings)
        settings_complete = True
        settings_uncertainty_reasons: list[str] = []
        incomplete_setting_kinds: list[SettingKind] = []
        hashes: list[tuple[str, str]] = [
            ("gpt.ini", gpt_hash)
        ]
        file_sizes: list[tuple[str, int]] = [("gpt.ini", len(gpt_data))]
        paths = (
            (
                "Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf",
                parse_gpttmpl,
                (
                    SettingKind.PRIVILEGE_RIGHT,
                    SettingKind.RESTRICTED_GROUP,
                    SettingKind.SECURITY_OPTION,
                ),
            ),
            ("Machine\\Registry.pol", parse_registry_pol, (SettingKind.REGISTRY,)),
        )
        for relative, parser, setting_kinds in paths:
            try:
                policy_data, policy_hash = read_file(share, root + "\\" + relative)
                hashes.append((relative, policy_hash))
                file_sizes.append((relative, len(policy_data)))
                settings.extend(parser(policy_data))
            except SysvolBudgetExceeded:
                raise
            except Exception as exc:
                if not _is_missing_policy_file_error(exc):
                    settings_complete = False
                    settings_uncertainty_reasons.append(
                        f"could not collect {relative}: {exc}"
                    )
                    incomplete_setting_kinds.extend(setting_kinds)
                    environment.warnings.append(
                        f"{original.name}: could not collect {relative}: {exc}"
                    )
        gpt_version = _gpt_version(gpt_data)
        if gpt_version is None:
            environment.warnings.append(
                f"{original.name}: gpt.ini version is missing or malformed"
            )
        environment.gpos[key] = replace(
            original,
            settings=tuple(settings),
            collector_gpt_readable=True,
            settings_complete=settings_complete,
            settings_uncertainty_reasons=tuple(settings_uncertainty_reasons),
            incomplete_setting_kinds=tuple(dict.fromkeys(incomplete_setting_kinds)),
            gpt_version=gpt_version,
            gpt_hashes=tuple(hashes),
            gpt_file_sizes=tuple(file_sizes),
        )
    try:
        smb.logoff()
    except Exception:
        pass
    return environment
