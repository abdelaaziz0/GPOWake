from __future__ import annotations

import struct

import pytest

from gpowake.models import RegistryOperation, SettingKind, Severity
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
    restricted = next(
        item for item in settings if item.kind is SettingKind.RESTRICTED_GROUP
    )
    assert restricted.dangerous is True
    assert restricted.severity is Severity.CRITICAL
    assert restricted.unexpected_trustees == ("S-1-5-21-1-2-3-1100",)
    option = next(item for item in settings if item.kind is SettingKind.SECURITY_OPTION)
    assert option.value == {"type": 4, "data": 5}


def test_invalid_template_is_contextualized() -> None:
    with pytest.raises(ValueError, match="invalid GptTmpl"):
        parse_gpttmpl("[broken")


def test_builtin_administrators_assignment_is_not_catalogued_as_dangerous() -> None:
    settings = parse_gpttmpl("[Privilege Rights]\nSeDebugPrivilege=*S-1-5-32-544\n")
    assert settings[0].dangerous is False


def test_gpttmpl_detects_utf16le_without_bom() -> None:
    content = "[Privilege Rights]\r\nSeDebugPrivilege=*S-1-5-11\r\n"
    settings = parse_gpttmpl(content.encode("utf-16-le"))
    assert settings[0].name == "SeDebugPrivilege"
    assert settings[0].dangerous is True


def _wide(value: str) -> bytes:
    return value.encode("utf-16-le")


def _registry_record(key: str, name: str, reg_type: int, raw: bytes) -> bytes:
    return (
        _wide("[")
        + _wide(f"{key};")
        + _wide(f"{name};")
        + struct.pack("<I", reg_type)
        + _wide(";")
        + struct.pack("<I", len(raw))
        + _wide(";")
        + raw
        + _wide("]")
    )


def test_registry_pol_single_dword() -> None:
    data = b"PReg" + struct.pack("<I", 1)
    data += _wide("[") + _wide("Software\\Policies\\Example;") + _wide("Enabled;")
    data += struct.pack("<I", 4) + _wide(";") + struct.pack("<I", 4) + _wide(";")
    data += struct.pack("<I", 1) + _wide("]")
    settings = parse_registry_pol(data)
    assert settings[0].name == "Software\\Policies\\Example\\Enabled"
    assert settings[0].value == {"type": 4, "data": 1}
    assert settings[0].registry_operation is RegistryOperation.SET_VALUE


def test_registry_pol_special_instructions_are_semantic_operations() -> None:
    key = "Software\\Policies\\Example"
    text = lambda value: _wide(value + "\x00")
    data = b"PReg" + struct.pack("<I", 1)
    data += _registry_record(key, "**DeleteValues", 1, text("One;Two"))
    data += _registry_record(key, "**Del.Three", 1, text(" "))
    data += _registry_record(key, "**DelVals.", 1, text(" "))
    data += _registry_record(key, "**DeleteKeys", 1, text("Child;Other"))
    data += _registry_record(key, "**SecureKey", 4, struct.pack("<I", 1))
    data += _registry_record(key, "**soft.Enabled", 4, struct.pack("<I", 1))

    settings = parse_registry_pol(data)
    assert [item.registry_operation for item in settings] == [
        RegistryOperation.DELETE_VALUE,
        RegistryOperation.DELETE_VALUE,
        RegistryOperation.DELETE_VALUE,
        RegistryOperation.DELETE_ALL_VALUES,
        RegistryOperation.DELETE_KEY,
        RegistryOperation.DELETE_KEY,
        RegistryOperation.SECURE_KEY,
        RegistryOperation.SET_IF_ABSENT,
    ]
    assert [item.registry_value_name for item in settings[:3]] == [
        "One",
        "Two",
        "Three",
    ]
    assert settings[-1].name == key + "\\Enabled"


def test_registry_pol_rejects_malformed_delete_instruction() -> None:
    data = b"PReg" + struct.pack("<I", 1)
    data += _registry_record(
        "Software\\Policies\\Example",
        "**Del.Enabled",
        1,
        _wide("not-a-space\x00"),
    )
    with pytest.raises(ValueError, match="one space"):
        parse_registry_pol(data)


def test_registry_pol_rejects_bad_signature() -> None:
    with pytest.raises(ValueError, match="signature"):
        parse_registry_pol(b"nope")


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LimitBlankPasswordUse", 0),
        ("MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\NoLMHash", 0),
        (
            "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA",
            0,
        ),
        (
            "MACHINE\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential",
            1,
        ),
    ],
)
def test_gpttmpl_classifies_narrow_dangerous_security_values(name, value) -> None:
    settings = parse_gpttmpl(f"[Registry Values]\n{name}=4,{value}\n")
    assert settings[0].dangerous is True
    assert settings[0].risk_rule_id == "GPOWAKE.SECURITY_BASELINE.v1"


def test_gpttmpl_does_not_flag_safe_security_value() -> None:
    settings = parse_gpttmpl(
        "[Registry Values]\n"
        "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LimitBlankPasswordUse=4,1\n"
    )
    assert settings[0].dangerous is False


def test_registry_pol_classifies_stored_autologon_password() -> None:
    password = _wide("secret\x00")
    data = b"PReg" + struct.pack("<I", 1)
    data += _wide("[")
    data += _wide("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon;")
    data += _wide("DefaultPassword;")
    data += struct.pack("<I", 1) + _wide(";")
    data += struct.pack("<I", len(password)) + _wide(";") + password + _wide("]")
    settings = parse_registry_pol(data)
    assert settings[0].dangerous is True
    assert settings[0].severity is Severity.CRITICAL
    assert settings[0].risk_rule_id == "GPOWAKE.REGISTRY_SECRET.v1"
