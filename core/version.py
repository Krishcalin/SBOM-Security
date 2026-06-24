"""Best-effort version comparison across ecosystems.

A single comparator that handles the common shapes — PEP 440, semver, Maven, Go
(`v` prefix) — well enough to classify a version change as an upgrade or a
downgrade. Build metadata (`+...`) is ignored; a pre-release (`-rc1`) sorts below
its release. Not a full spec implementation; ambiguous mixed segments fall back to
string comparison.
"""

from __future__ import annotations

import re
from itertools import zip_longest

_SEG = re.compile(r"[._]")


def _split(v: str) -> tuple[str, str]:
    v = v.strip().lstrip("vV").split("+", 1)[0]   # drop leading v and build metadata
    main, _, pre = v.partition("-")
    return main, pre


def _parts(main: str) -> list:
    out: list = []
    for p in _SEG.split(main):
        out.append(int(p) if p.isdigit() else p)
    return out


def compare(a: str, b: str) -> int:
    """Return -1 if a<b, 0 if equal, 1 if a>b."""
    main_a, pre_a = _split(a)
    main_b, pre_b = _split(b)
    for x, y in zip_longest(_parts(main_a), _parts(main_b), fillvalue=0):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        sx, sy = str(x), str(y)
        if sx != sy:
            return -1 if sx < sy else 1
    # main equal: a release outranks a pre-release of the same main version
    if pre_a == pre_b:
        return 0
    if not pre_a:
        return 1
    if not pre_b:
        return -1
    return -1 if pre_a < pre_b else 1
