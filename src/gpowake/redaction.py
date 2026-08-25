from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
from typing import Any

from .models import ValueSensitivity


SECRET_MARKER: dict[str, bool] = {"secret_present": True}
_SECRET_KEYS = frozenset(
    {
        "password",
        "defaultpassword",
        "cleartextpassword",
        "cpassword",
        "passwd",
        "lmhash",
        "nthash",
        "hashes",
        "credentialsecret",
    }
)


def secret_marker() -> dict[str, bool]:
    """Return a fresh, non-reversible marker for a destroyed secret value."""

    return dict(SECRET_MARKER)


def redact_value(value: Any, sensitivity: ValueSensitivity | str) -> Any:
    """Destroy a sensitive value regardless of its runtime representation."""

    if ValueSensitivity(sensitivity) is ValueSensitivity.SECRET:
        if (
            isinstance(value, Mapping)
            and value.get("secret_present") is True
            and set(value).issubset({"type", "secret_present"})
        ):
            return redact_sensitive(value)
        return secret_marker()
    return redact_sensitive(value)


def redact_sensitive(value: Any) -> Any:
    """Recursively redact known secret fields and sensitivity-labelled values.

    This is a final fail-closed boundary, not the primary protection. Parsers
    must destroy secrets before constructing the model.
    """

    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        sensitivity = value.get("value_sensitivity", value.get("sensitivity"))
        secret_context = sensitivity in {
            ValueSensitivity.SECRET,
            ValueSensitivity.SECRET.value,
        }
        result: dict[Any, Any] = {}
        for key, item in value.items():
            key_text = str(key).replace("_", "").casefold()
            if key_text in _SECRET_KEYS:
                result[key] = secret_marker()
            elif secret_context and key in {
                "value",
                "dormant_value",
                "result_value",
                "current_value",
            }:
                result[key] = redact_value(item, ValueSensitivity.SECRET)
            else:
                result[key] = redact_sensitive(item)
        return result
    if isinstance(value, tuple):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    return value


def display_value(value: Any, sensitivity: ValueSensitivity | str) -> str:
    safe = redact_value(value, sensitivity)
    if safe == SECRET_MARKER:
        return "<redacted: secret present>"
    return str(safe)
