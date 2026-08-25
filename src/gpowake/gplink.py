from __future__ import annotations

import re

from .models import Link


_LINK_RE = re.compile(r"\[(?:LDAP://)?([^;\]]+);(\d+)\]", re.IGNORECASE)


def parse_gplink(value: str | None) -> tuple[Link, ...]:
    """Parse AD's ordered, single-valued gPLink attribute.

    The first segment in the stored value is link order 1 (highest precedence at
    that SOM). Unknown option bits are preserved.
    """
    if not value:
        return ()
    matches = list(_LINK_RE.finditer(value))
    if not matches or "".join(m.group(0) for m in matches) != value.strip():
        raise ValueError(f"malformed gPLink value: {value!r}")
    links: list[Link] = []
    for index, match in enumerate(matches, start=1):
        options = int(match.group(2))
        if options > 0xFFFFFFFF:
            raise ValueError(f"gPLink options are outside uint32 range: {options}")
        links.append(
            Link(
                gpo_dn=match.group(1).strip(),
                options=options,
                order=index,
            )
        )
    return tuple(links)


def serialize_gplink(links: tuple[Link, ...] | list[Link]) -> str:
    ordered = sorted(links, key=lambda link: link.order)
    return "".join(f"[LDAP://{link.gpo_dn};{link.options}]" for link in ordered)


def reorder_link(
    links: tuple[Link, ...], gpo_dn: str, old_order: int, new_order: int
) -> tuple[Link, ...]:
    ordered = list(sorted(links, key=lambda link: link.order))
    index = next(
        (
            i
            for i, link in enumerate(ordered)
            if link.gpo_dn.casefold() == gpo_dn.casefold() and link.order == old_order
        ),
        None,
    )
    if index is None:
        raise KeyError(f"link not found: {gpo_dn} order {old_order}")
    link = ordered.pop(index)
    destination = max(0, min(new_order - 1, len(ordered)))
    ordered.insert(destination, link)
    return tuple(
        Link(item.gpo_dn, item.options, order)
        for order, item in enumerate(ordered, start=1)
    )
