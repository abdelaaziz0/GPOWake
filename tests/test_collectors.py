from __future__ import annotations

from gpowake.collectors.ldap import _parent_dn
from gpowake.collectors.sysvol import _gpt_version, _unc_parts


def test_parent_dn_honors_escaped_comma() -> None:
    assert _parent_dn(r"CN=Last\, First,OU=People,DC=corp,DC=local") == (
        "OU=People,DC=corp,DC=local"
    )


def test_sysvol_unc_and_version_parsing() -> None:
    share, path = _unc_parts(
        r"\\corp.local\SYSVOL\corp.local\Policies\{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"
    )
    assert share.casefold() == "sysvol"
    assert path.startswith("corp.local\\Policies")
    assert _gpt_version(b"[General]\r\nVersion=42\r\n") == 42
