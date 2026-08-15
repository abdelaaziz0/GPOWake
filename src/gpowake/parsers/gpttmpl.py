from __future__ import annotations

import configparser
import io
from pathlib import Path

from ..catalog import SECURITY_CSE_GUID, assess_setting
from ..models import Setting, SettingKind


class _CaseConfigParser(configparser.RawConfigParser):
    def optionxform(self, optionstr: str) -> str:
        return optionstr


def _decode(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    for encoding in ("utf-8-sig", "utf-16-le", "cp1252"):
        try:
            decoded = data.decode(encoding)
            if "[" in decoded and "]" in decoded:
                return decoded.lstrip("\ufeff")
        except UnicodeDecodeError:
            continue
    raise ValueError("GptTmpl.inf has no supported text encoding")


def _csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip().lstrip("*") for item in value.split(",") if item.strip())


def _registry_value(value: str) -> dict[str, object]:
    type_text, separator, raw = value.partition(",")
    if not separator:
        return {"type": type_text.strip(), "data": ""}
    reg_type: int | str
    try:
        reg_type = int(type_text.strip())
    except ValueError:
        reg_type = type_text.strip()
    data: object = raw.strip()
    if reg_type == 4:
        try:
            data = int(str(data), 0)
        except ValueError:
            pass
    return {"type": reg_type, "data": data}


def parse_gpttmpl(data: bytes | str) -> tuple[Setting, ...]:
    text = data if isinstance(data, str) else _decode(data)
    parser = _CaseConfigParser(strict=False, delimiters=("="), interpolation=None)
    try:
        parser.read_file(io.StringIO(text))
    except configparser.Error as exc:
        raise ValueError(f"invalid GptTmpl.inf: {exc}") from exc

    settings: list[Setting] = []
    if parser.has_section("Privilege Rights"):
        for name, raw in parser.items("Privilege Rights"):
            settings.append(
                assess_setting(
                    Setting(
                        kind=SettingKind.PRIVILEGE_RIGHT,
                        name=name.strip(),
                        value=_csv(raw),
                        required_extension=SECURITY_CSE_GUID,
                    )
                )
            )
    if parser.has_section("Group Membership"):
        for name, raw in parser.items("Group Membership"):
            settings.append(
                Setting(
                    kind=SettingKind.RESTRICTED_GROUP,
                    name=name.strip().replace("__", "/"),
                    value=_csv(raw),
                    required_extension=SECURITY_CSE_GUID,
                )
            )
    if parser.has_section("Registry Values"):
        for name, raw in parser.items("Registry Values"):
            settings.append(
                Setting(
                    kind=SettingKind.SECURITY_OPTION,
                    name=name.strip(),
                    value=_registry_value(raw),
                    required_extension=SECURITY_CSE_GUID,
                )
            )
    return tuple(settings)


def parse_gpttmpl_file(path: str | Path) -> tuple[Setting, ...]:
    return parse_gpttmpl(Path(path).read_bytes())
