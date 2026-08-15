from __future__ import annotations

import struct

import pytest

from gpowake.models import SettingKind, Severity
from gpowake.parsers.gpttmpl import parse_gpttmpl
from gpowake.parsers.registry_pol import parse_registry_pol


def test_gpttmpl_privileges_groups_and_security_options() -> None:
    content = """[Unicode]
Unicode=yes
[Privilege Rights]
SeDebugPrivilege = *S-1-5-11,DOMAIN\\Operators
SeChangeNotifyPrivilege = *S-1-1-0
[Group Membership]
*S-1-5-32-544__Members = *S-1-5-21-1-2-3-1100
[Registry Values]
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel=4,5
"""
    settings = parse_gpttmpl(content.encode("utf-16"))
    debug = next(item for item in settings if item.name == "SeDebugPrivilege")
    assert debug.value == ("S-1-5-11", "DOMAIN\\Operators")
    assert debug.dangerous is True
    assert debug.severity is Severity.CRITICAL
    assert any(item.kind is SettingKind.RESTRICTED_GROUP for item in settings)
    option = next(item for item in settings if item.kind is SettingKind.SECURITY_OPTION)
    assert option.value == {"type": 4, "data": 5}


def test_invalid_template_is_contextualized() -> None:
    with pytest.raises(ValueError, match="invalid GptTmpl"):
        parse_gpttmpl("[broken")


def test_builtin_administrators_assignment_is_not_catalogued_as_dangerous() -> None:
    settings = parse_gpttmpl("[Privilege Rights]\nSeDebugPrivilege=*S-1-5-32-544\n")
    assert settings[0].dangerous is False


def _wide(value: str) -> bytes:
    return value.encode("utf-16-le")


def test_registry_pol_single_dword() -> None:
    data = b"PReg" + struct.pack("<I", 1)
    data += _wide("[") + _wide("Software\\Policies\\Example;") + _wide("Enabled;")
    data += struct.pack("<I", 4) + _wide(";") + struct.pack("<I", 4) + _wide(";")
    data += struct.pack("<I", 1) + _wide("]")
    settings = parse_registry_pol(data)
    assert settings[0].name == "Software\\Policies\\Example\\Enabled"
    assert settings[0].value == {"type": 4, "data": 1}


def test_registry_pol_rejects_bad_signature() -> None:
    with pytest.raises(ValueError, match="signature"):
        parse_registry_pol(b"nope")
