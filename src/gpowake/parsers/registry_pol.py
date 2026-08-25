from __future__ import annotations

import struct
from pathlib import Path

from ..catalog import REGISTRY_CSE_GUID, assess_setting
from ..models import Setting, SettingKind


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
        settings.append(
            assess_setting(Setting(
                kind=SettingKind.REGISTRY,
                name=f"{key}\\{value_name}",
                value={"type": reg_type, "data": _decode_value(reg_type, raw)},
                required_extension=REGISTRY_CSE_GUID,
            ))
        )
    return tuple(settings)


def parse_registry_pol_file(path: str | Path) -> tuple[Setting, ...]:
    return parse_registry_pol(Path(path).read_bytes())
