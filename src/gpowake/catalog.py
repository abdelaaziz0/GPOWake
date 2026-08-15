from __future__ import annotations

from dataclasses import replace
from typing import Any

from .models import Setting, SettingKind, Severity, normalize_sid


SECURITY_CSE_GUID = "827d319e-6eac-11d2-a4ea-00c04f79f83a"
REGISTRY_CSE_GUID = "35378eac-683f-11d2-a89a-00c04fbbcfa2"


_PRIVILEGE_RULES: dict[str, tuple[Severity, str]] = {
    "sedebugprivilege": (
        Severity.CRITICAL,
        "permits debugging and code access to protected processes",
    ),
    "setcbprivilege": (
        Severity.CRITICAL,
        "permits acting as part of the operating system",
    ),
    "secreatetokenprivilege": (
        Severity.CRITICAL,
        "permits creation of arbitrary access tokens",
    ),
    "seassignprimarytokenprivilege": (
        Severity.CRITICAL,
        "permits replacement of process-level tokens",
    ),
    "seimpersonateprivilege": (
        Severity.CRITICAL,
        "permits impersonation after authentication",
    ),
    "seloaddriverprivilege": (Severity.CRITICAL, "permits loading kernel drivers"),
    "setakeownershipprivilege": (
        Severity.HIGH,
        "permits taking ownership of securable objects",
    ),
    "serestoreprivilege": (
        Severity.HIGH,
        "permits bypassing object write checks during restore",
    ),
    "sebackupprivilege": (
        Severity.HIGH,
        "permits bypassing object read checks during backup",
    ),
    "serelabelprivilege": (Severity.HIGH, "permits modifying object integrity labels"),
    "semanagevolumeprivilege": (Severity.HIGH, "permits low-level volume maintenance"),
    "setrustedcredmanaccessprivilege": (
        Severity.CRITICAL,
        "permits access to Credential Manager as a trusted caller",
    ),
    "semachineaccountprivilege": (
        Severity.HIGH,
        "permits adding computers to the domain",
    ),
}

_BROAD_SIDS = {"S-1-1-0", "S-1-5-11"}
_EXPECTED_PRIVILEGED_SIDS = {
    "S-1-5-6",  # Service
    "S-1-5-18",  # Local System
    "S-1-5-19",  # Local Service
    "S-1-5-20",  # Network Service
    "S-1-5-32-544",  # Builtin Administrators
    "S-1-5-32-551",  # Backup Operators
}


def assess_setting(setting: Setting) -> Setting:
    """Attach the built-in danger classification while preserving explicit rules."""
    if setting.dangerous:
        return setting
    if setting.kind is not SettingKind.PRIVILEGE_RIGHT:
        return setting
    rule = _PRIVILEGE_RULES.get(setting.name.casefold())
    if not rule or not setting.value:
        return setting
    severity, rationale = rule
    values = {normalize_sid(str(item).lstrip("*")) for item in setting.value}
    # SeMachineAccountPrivilege is normal for Authenticated Users in many domains;
    # it is only elevated to a finding when a broad/default population receives it.
    if setting.name.casefold() == "semachineaccountprivilege":
        is_broad = bool(values & _BROAD_SIDS) or any(
            sid.endswith("-513") for sid in values
        )
        if not is_broad:
            return setting
    else:
        unexpected = {
            sid
            for sid in values
            if sid not in _EXPECTED_PRIVILEGED_SIDS
            and not sid.endswith(("-512", "-518", "-519"))
        }
        if not unexpected:
            return setting
    return replace(setting, dangerous=True, severity=severity, rationale=rationale)


def setting_from_dict(data: dict[str, Any]) -> Setting:
    kind = SettingKind(data["kind"])
    value = data.get("value")
    if isinstance(value, list):
        value = tuple(value)
    required = data.get("required_extension")
    if required is None:
        required = (
            SECURITY_CSE_GUID
            if kind
            in {
                SettingKind.PRIVILEGE_RIGHT,
                SettingKind.RESTRICTED_GROUP,
                SettingKind.SECURITY_OPTION,
            }
            else REGISTRY_CSE_GUID
        )
    setting = Setting(
        kind=kind,
        name=data["name"],
        value=value,
        dangerous=bool(data.get("dangerous", False)),
        severity=Severity(data.get("severity", "MEDIUM")),
        rationale=data.get("rationale", ""),
        required_extension=required,
    )
    return assess_setting(setting)
