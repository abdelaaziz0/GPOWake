from __future__ import annotations

import struct
from pathlib import Path

from ..catalog import REGISTRY_CSE_GUID, assess_setting
from ..models import (
    RegistryOperation,
    Setting,
    SettingKind,
    ValueSensitivity,
)


REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_MULTI_SZ = 7
REG_QWORD = 11


def _expect(data: bytes, offset: int, token: bytes) -> int:
    if data[offset : offset + len(token)] != token:
        raise ValueError(
            f"malformed Registry.pol record at byte {offset}: expected {token!r}"
        )
    return offset + len(token)


def _wide_until(data: bytes, offset: int, delimiter: str) -> tuple[str, int]:
    marker = delimiter.encode("utf-16-le")
    end = data.find(marker, offset)
    while end >= 0 and (end - offset) % 2:
        end = data.find(marker, end + 1)
    if end < 0:
        raise ValueError(f"malformed Registry.pol string at byte {offset}")
    try:
        value = data[offset:end].decode("utf-16-le").rstrip("\x00")
    except UnicodeDecodeError as exc:
        raise ValueError(f"malformed Registry.pol string at byte {offset}") from exc
    return value, end + len(marker)


def _decode_value(reg_type: int, raw: bytes) -> object:
    if reg_type in (REG_SZ, REG_EXPAND_SZ):
        if len(raw) % 2:
            raise ValueError("malformed odd-length Registry.pol string value")
        return raw.decode("utf-16-le", errors="strict").rstrip("\x00")
    if reg_type == REG_MULTI_SZ:
        if len(raw) % 2:
            raise ValueError("malformed odd-length Registry.pol multi-string value")
        return tuple(
            item
            for item in raw.decode("utf-16-le", errors="strict")
            .rstrip("\x00")
            .split("\x00")
            if item
        )
    if reg_type == REG_DWORD and len(raw) == 4:
        return struct.unpack("<I", raw)[0]
    if reg_type == REG_QWORD and len(raw) == 8:
        return struct.unpack("<Q", raw)[0]
    return raw.hex()


def _is_default_password(name: str) -> bool:
    normalized = name.replace("/", "\\").casefold()
    for prefix in ("machine\\", "hkey_local_machine\\", "hklm\\"):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]
            break
    return (
        normalized
        == "software\\microsoft\\windows nt\\currentversion\\winlogon\\defaultpassword"
    )


def _require_type(value_name: str, reg_type: int, expected: int) -> None:
    if reg_type != expected:
        raise ValueError(
            f"Registry.pol instruction {value_name} requires type {expected}, "
            f"got {reg_type}"
        )


def _registry_setting(
    key: str,
    value_name: str | None,
    operation: RegistryOperation,
    value: object,
) -> Setting:
    name = key if value_name is None else f"{key}\\{value_name}"
    sensitivity = ValueSensitivity.PUBLIC
    if (
        operation in {RegistryOperation.SET_VALUE, RegistryOperation.SET_IF_ABSENT}
        and _is_default_password(name)
        and isinstance(value, dict)
        and isinstance(value.get("data"), str)
        and bool(value["data"])
    ):
        # The semantic target is resolved before classification, so spellings
        # such as **soft.DefaultPassword cannot bypass immediate destruction.
        value = {"type": value.get("type"), "secret_present": True}
        sensitivity = ValueSensitivity.SECRET
    return assess_setting(
        Setting(
            kind=SettingKind.REGISTRY,
            name=name,
            value=value,
            required_extension=REGISTRY_CSE_GUID,
            value_sensitivity=sensitivity,
            registry_operation=operation,
            registry_key=key,
            registry_value_name=value_name,
        )
    )


def _semantic_settings(
    key: str, value_name: str, reg_type: int, raw: bytes
) -> tuple[Setting, ...]:
    instruction = value_name.casefold()
    if instruction == "**deletevalues":
        _require_type(value_name, reg_type, REG_SZ)
        decoded = _decode_value(reg_type, raw)
        assert isinstance(decoded, str)
        return tuple(
            _registry_setting(
                key,
                target,
                RegistryOperation.DELETE_VALUE,
                None,
            )
            for target in decoded.split(";")
            if target
        )
    if instruction.startswith("**del."):
        _require_type(value_name, reg_type, REG_SZ)
        target = value_name[len("**Del.") :]
        if not target:
            raise ValueError("Registry.pol **Del instruction lacks a value name")
        decoded = _decode_value(reg_type, raw)
        if decoded != " ":
            raise ValueError("Registry.pol **Del data must be one space")
        return (
            _registry_setting(
                key,
                target,
                RegistryOperation.DELETE_VALUE,
                None,
            ),
        )
    if instruction == "**delvals.":
        _require_type(value_name, reg_type, REG_SZ)
        decoded = _decode_value(reg_type, raw)
        if decoded != " ":
            raise ValueError("Registry.pol **DelVals. data must be one space")
        return (
            _registry_setting(
                key,
                None,
                RegistryOperation.DELETE_ALL_VALUES,
                None,
            ),
        )
    if instruction == "**deletekeys":
        _require_type(value_name, reg_type, REG_SZ)
        decoded = _decode_value(reg_type, raw)
        assert isinstance(decoded, str)
        return tuple(
            _registry_setting(
                f"{key}\\{target}",
                None,
                RegistryOperation.DELETE_KEY,
                None,
            )
            for target in decoded.split(";")
            if target
        )
    if instruction == "**securekey":
        _require_type(value_name, reg_type, REG_DWORD)
        return (
            _registry_setting(
                key,
                None,
                RegistryOperation.SECURE_KEY,
                {"type": reg_type, "data": _decode_value(reg_type, raw)},
            ),
        )
    if instruction.startswith("**soft."):
        target = value_name[len("**soft.") :]
        if not target:
            raise ValueError("Registry.pol **soft instruction lacks a value name")
        return (
            _registry_setting(
                key,
                target,
                RegistryOperation.SET_IF_ABSENT,
                {"type": reg_type, "data": _decode_value(reg_type, raw)},
            ),
        )
    return (
        _registry_setting(
            key,
            value_name,
            RegistryOperation.SET_VALUE,
            {"type": reg_type, "data": _decode_value(reg_type, raw)},
        ),
    )


def parse_registry_pol(data: bytes) -> tuple[Setting, ...]:
    if len(data) < 8 or data[:4] != b"PReg":
        raise ValueError("Registry.pol signature is missing")
    version = struct.unpack_from("<I", data, 4)[0]
    if version != 1:
        raise ValueError(f"unsupported Registry.pol version {version}")
    offset = 8
    settings: list[Setting] = []
    while offset < len(data):
        # Some writers leave a UTF-16 NUL between records.
        while data[offset : offset + 2] == b"\x00\x00":
            offset += 2
        if offset >= len(data):
            break
        offset = _expect(data, offset, b"[\x00")
        key, offset = _wide_until(data, offset, ";")
        value_name, offset = _wide_until(data, offset, ";")
        if offset + 4 > len(data):
            raise ValueError("truncated Registry.pol type")
        reg_type = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        offset = _expect(data, offset, b";\x00")
        if offset + 4 > len(data):
            raise ValueError("truncated Registry.pol size")
        size = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        offset = _expect(data, offset, b";\x00")
        if offset + size > len(data):
            raise ValueError("truncated Registry.pol data")
        raw = data[offset : offset + size]
        offset += size
        offset = _expect(data, offset, b"]\x00")
        settings.extend(_semantic_settings(key, value_name, reg_type, raw))
    return tuple(settings)


def parse_registry_pol_file(path: str | Path) -> tuple[Setting, ...]:
    return parse_registry_pol(Path(path).read_bytes())
