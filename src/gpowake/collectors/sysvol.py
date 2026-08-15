from __future__ import annotations

import configparser
import io
from dataclasses import replace

from ..models import Environment
from ..parsers.gpttmpl import parse_gpttmpl
from ..parsers.registry_pol import parse_registry_pol
from .ldap import CollectionConfig


def _unc_parts(unc: str) -> tuple[str, str]:
    parts = [part for part in unc.replace("/", "\\").split("\\") if part]
    if len(parts) < 3:
        raise ValueError(f"invalid gPCFileSysPath {unc!r}")
    return parts[1], "\\".join(parts[2:])


def _gpt_version(data: bytes) -> int | None:
    text = data.decode("utf-8-sig", errors="replace")
    parser = configparser.ConfigParser()
    parser.read_file(io.StringIO(text))
    try:
        return parser.getint("General", "Version")
    except (configparser.Error, ValueError):
        return None


def collect_sysvol(environment: Environment, config: CollectionConfig) -> Environment:
    try:
        from impacket.smbconnection import SMBConnection  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - optional extra
        raise RuntimeError(
            "SYSVOL collection requires the 'collect' extra (impacket)"
        ) from exc

    remote_name = config.dc_host or config.domain
    smb = SMBConnection(remote_name, config.dc_ip)
    auth = config.auth
    if auth.kerberos:
        smb.kerberosLogin(
            auth.username,
            auth.password,
            auth.auth_domain or config.domain,
            auth.lmhash,
            auth.nthash,
            kdcHost=config.dc_ip,
            useCache=True,
        )
    else:
        smb.login(
            auth.username, auth.password, auth.auth_domain, auth.lmhash, auth.nthash
        )

    def read_file(share: str, path: str) -> bytes:
        chunks: list[bytes] = []
        smb.getFile(share, path, chunks.append)
        return b"".join(chunks)

    for key, original in list(environment.gpos.items()):
        unc = original.file_sys_path or (
            f"\\\\{config.domain}\\SYSVOL\\{config.domain}\\Policies\\{original.guid}"
        )
        try:
            share, root = _unc_parts(unc)
            gpt_data = read_file(share, root + "\\gpt.ini")
        except Exception as exc:
            environment.warnings.append(
                f"{original.name}: cannot read GPT from {unc}: {exc}"
            )
            environment.gpos[key] = replace(original, gpt_readable=False)
            continue
        settings = list(original.settings)
        paths = (
            ("Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf", parse_gpttmpl),
            ("Machine\\Registry.pol", parse_registry_pol),
        )
        for relative, parser in paths:
            try:
                settings.extend(parser(read_file(share, root + "\\" + relative)))
            except Exception as exc:
                # Missing optional policy files are normal; malformed/read-denied
                # files are retained as warnings without discarding other CSEs.
                message = str(exc)
                if (
                    "STATUS_OBJECT_NAME_NOT_FOUND" not in message
                    and "STATUS_NO_SUCH_FILE" not in message
                ):
                    environment.warnings.append(
                        f"{original.name}: could not collect {relative}: {exc}"
                    )
        environment.gpos[key] = replace(
            original,
            settings=tuple(settings),
            gpt_readable=True,
            gpt_version=_gpt_version(gpt_data),
        )
    try:
        smb.logoff()
    except Exception:
        pass
    return environment
