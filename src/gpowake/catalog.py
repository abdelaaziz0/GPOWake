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
PRIVILEGE_ASSIGNMENT_RULE_ID = "GPOWAKE.PRIVILEGE_ASSIGNMENT.v1"
RESTRICTED_ADMIN_RULE_ID = "GPOWAKE.RESTRICTED_ADMINISTRATORS.v1"
SECURITY_BASELINE_RULE_ID = "GPOWAKE.SECURITY_BASELINE.v1"
REGISTRY_SECRET_RULE_ID = "GPOWAKE.REGISTRY_SECRET.v1"
BUILTIN_ADMINISTRATORS = "S-1-5-32-544"

# Groups that are already full-domain or full-machine administrators. Assigning
# any privilege to them changes nothing about their effective power, so it is
# never elevated to a finding regardless of which privilege it is.
_ALWAYS_EXPECTED_SIDS = {
    "S-1-5-18",  # Local System
    "S-1-5-32-544",  # Builtin Administrators
}
# Per-privilege default holders. A privilege granted only to identities that
# already hold it by Windows default is expected; anything else is a finding.
# Deliberately narrow: e.g. Backup Operators is default for Se(Backup|Restore)
# but NOT for SeDebug/SeTcb, so those on Backup Operators are still flagged.
_PRIVILEGE_EXPECTED_SIDS: dict[str, set[str]] = {
    "seimpersonateprivilege": {
        "S-1-5-6",  # Service
        "S-1-5-19",  # Local Service
        "S-1-5-20",  # Network Service
    },
    "seassignprimarytokenprivilege": {
        "S-1-5-19",  # Local Service
        "S-1-5-20",  # Network Service
    },
    "sebackupprivilege": {
        "S-1-5-32-551",  # Backup Operators
        "S-1-5-32-549",  # Server Operators
    },
    "serestoreprivilege": {
        "S-1-5-32-551",  # Backup Operators
        "S-1-5-32-549",  # Server Operators
    },
}


def _expected_sids(privilege_cf: str) -> set[str]:
    return _ALWAYS_EXPECTED_SIDS | _PRIVILEGE_EXPECTED_SIDS.get(privilege_cf, set())


def _setting_data(setting: Setting) -> object:
    return setting.value.get("data") if isinstance(setting.value, dict) else None


def _normalized_registry_name(name: str) -> str:
    result = name.replace("/", "\\").casefold()
    for prefix in ("machine\\", "hkey_local_machine\\", "hklm\\"):
        if result.startswith(prefix):
            return result[len(prefix) :]
    return result


def _assess_restricted_group(
    setting: Setting, trusted_admin_sids: set[str] | frozenset[str]
) -> Setting:
    group, separator, relationship = setting.name.partition("/")
    if not separator or not isinstance(setting.value, (list, tuple, set)):
        return setting
    group_id = normalize_sid(group.lstrip("*"))
    values = {
        normalize_sid(str(item).lstrip("*")) for item in setting.value if str(item)
    }
    expected = _ALWAYS_EXPECTED_SIDS | {
        normalize_sid(sid) for sid in trusted_admin_sids
    }
    unexpected: set[str] = set()
    relationship_cf = relationship.casefold()
    if group_id == BUILTIN_ADMINISTRATORS and relationship_cf == "members":
        unexpected = values - expected
    elif relationship_cf == "memberof" and BUILTIN_ADMINISTRATORS in values:
        if group_id not in expected:
            unexpected = {group_id}
    else:
        return setting
    return replace(
        setting,
        dangerous=bool(unexpected),
        severity=Severity.CRITICAL,
        rationale=(
            "places a non-administrative trustee in the local Administrators group"
            if unexpected
            else "changes local Administrators membership only to expected administrators"
        ),
        risk_rule_id=RESTRICTED_ADMIN_RULE_ID,
        unexpected_trustees=tuple(sorted(unexpected)),
    )


def _assess_security_value(setting: Setting) -> Setting:
    name = _normalized_registry_name(setting.name)
    data = _setting_data(setting)
    rules: dict[str, tuple[object, Severity, str, str]] = {
        "system\\currentcontrolset\\control\\lsa\\limitblankpassworduse": (
            0,
            Severity.HIGH,
            "permits remote use of local accounts with blank passwords",
            SECURITY_BASELINE_RULE_ID,
        ),
        "system\\currentcontrolset\\control\\lsa\\nolmhash": (
            0,
            Severity.HIGH,
            "permits storage of legacy LM password hashes",
            SECURITY_BASELINE_RULE_ID,
        ),
        "software\\microsoft\\windows\\currentversion\\policies\\system\\enablelua": (
            0,
            Severity.HIGH,
            "disables User Account Control",
            SECURITY_BASELINE_RULE_ID,
        ),
        "system\\currentcontrolset\\control\\securityproviders\\wdigest\\uselogoncredential": (
            1,
            Severity.CRITICAL,
            "enables WDigest plaintext logon credential caching",
            SECURITY_BASELINE_RULE_ID,
        ),
    }
    rule = rules.get(name)
    if rule is not None and data == rule[0]:
        return replace(
            setting,
            dangerous=True,
            severity=rule[1],
            rationale=rule[2],
            risk_rule_id=rule[3],
        )
    if (
        setting.kind is SettingKind.REGISTRY
        and name
        == "software\\microsoft\\windows nt\\currentversion\\winlogon\\defaultpassword"
        and isinstance(data, str)
        and bool(data)
    ):
        return replace(
            setting,
            dangerous=True,
            severity=Severity.CRITICAL,
            rationale="stores an AutoLogon password in policy-managed registry data",
            risk_rule_id=REGISTRY_SECRET_RULE_ID,
        )
    if setting.risk_rule_id in {
        SECURITY_BASELINE_RULE_ID,
        REGISTRY_SECRET_RULE_ID,
    }:
        return replace(
            setting,
            dangerous=False,
            rationale="",
            unexpected_trustees=(),
        )
    return setting


def assess_setting(
    setting: Setting, trusted_admin_sids: set[str] | frozenset[str] = frozenset()
) -> Setting:
    """Attach the built-in danger rule using exact trusted-domain admin SIDs.

    Automatic decisions are re-evaluable because they carry ``risk_rule_id``.
    A dangerous setting without a rule ID is an explicit snapshot override and
    is preserved. RID suffixes are never trusted without a matching domain SID.
    """

    if setting.dangerous and setting.risk_rule_id is None:
        return setting
    if setting.kind is SettingKind.RESTRICTED_GROUP:
        return _assess_restricted_group(setting, trusted_admin_sids)
    if setting.kind in {SettingKind.SECURITY_OPTION, SettingKind.REGISTRY}:
        return _assess_security_value(setting)
    if setting.kind is not SettingKind.PRIVILEGE_RIGHT:
        return setting
    name_cf = setting.name.casefold()
    rule = _PRIVILEGE_RULES.get(name_cf)
    if not rule or not setting.value:
        return setting
    severity, rationale = rule
    values = {normalize_sid(str(item).lstrip("*")) for item in setting.value}
    # SeMachineAccountPrivilege is normal for Authenticated Users in many domains;
    # it is only elevated to a finding when a broad/default population receives it.
    if name_cf == "semachineaccountprivilege":
        is_broad = bool(values & _BROAD_SIDS) or any(
            sid.endswith("-513") for sid in values
        )
        if not is_broad:
            return setting
    else:
        expected = _expected_sids(name_cf) | {
            normalize_sid(sid) for sid in trusted_admin_sids
        }
        unexpected = {
            sid
            for sid in values
            if sid not in expected
        }
        if not unexpected:
            return replace(
                setting,
                dangerous=False,
                risk_rule_id=PRIVILEGE_ASSIGNMENT_RULE_ID,
                unexpected_trustees=(),
            )
    unexpected_values = tuple(sorted(values - _expected_sids(name_cf)))
    if name_cf != "semachineaccountprivilege":
        unexpected_values = tuple(sorted(unexpected))
    return replace(
        setting,
        dangerous=True,
        severity=severity,
        rationale=rationale,
        risk_rule_id=PRIVILEGE_ASSIGNMENT_RULE_ID,
        unexpected_trustees=unexpected_values,
    )


def setting_from_dict(data: dict[str, Any]) -> Setting:
    kind = SettingKind(data["kind"])
    value = data.get("value")
    if isinstance(value, list):
        value = tuple(value)
    if kind in {SettingKind.PRIVILEGE_RIGHT, SettingKind.RESTRICTED_GROUP} and not isinstance(
        value, tuple
    ):
        raise ValueError(f"{kind.value} setting value must be a JSON array")
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
    dangerous_value = data.get("dangerous", False)
    if type(dangerous_value) is not bool:
        raise ValueError("Setting.dangerous must be a JSON boolean")
    setting = Setting(
        kind=kind,
        name=data["name"],
        value=value,
        dangerous=dangerous_value,
        severity=Severity(data.get("severity", "MEDIUM")),
        rationale=data.get("rationale", ""),
        required_extension=required,
        risk_rule_id=data.get("risk_rule_id"),
        unexpected_trustees=tuple(data.get("unexpected_trustees", ())),
    )
    return assess_setting(setting)
