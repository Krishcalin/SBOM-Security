"""Dependency drift — diff two component sets into added/removed/up/downgraded.

Components are grouped by (ecosystem, name); the version sets are compared. A name
that gains one version and loses one is an upgrade or downgrade (decided by the
version comparator); broader churn is reported as discrete added/removed entries.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from core.models import Component
from core.version import compare


@dataclass
class Change:
    ecosystem: str
    name: str
    old_version: str | None
    new_version: str | None
    kind: str   # added | removed | upgraded | downgraded


@dataclass
class DriftResult:
    changes: list[Change] = field(default_factory=list)
    unchanged: int = 0

    @property
    def has_changes(self) -> bool:
        return bool(self.changes)

    def by_kind(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for c in self.changes:
            counts[c.kind] = counts.get(c.kind, 0) + 1
        return counts


def _index(components: list[Component]) -> dict[tuple[str, str], tuple[str, set[str]]]:
    idx: dict[tuple[str, str], tuple[str, set[str]]] = {}
    grouped: dict[tuple[str, str], set[str]] = defaultdict(set)
    names: dict[tuple[str, str], str] = {}
    for c in components:
        key = (c.ecosystem, c.name.lower())
        grouped[key].add(c.version)
        names.setdefault(key, c.name)
    for key, versions in grouped.items():
        idx[key] = (names[key], versions)
    return idx


def diff(old: list[Component], new: list[Component]) -> DriftResult:
    old_idx, new_idx = _index(old), _index(new)
    result = DriftResult()
    for key in sorted(old_idx.keys() | new_idx.keys()):
        eco, _ = key
        name = new_idx.get(key, old_idx.get(key))[0]
        old_vers = old_idx.get(key, ("", set()))[1]
        new_vers = new_idx.get(key, ("", set()))[1]
        added, removed = new_vers - old_vers, old_vers - new_vers
        result.unchanged += len(old_vers & new_vers)
        if not added and not removed:
            continue
        if len(added) == 1 and len(removed) == 1:
            o, n = next(iter(removed)), next(iter(added))
            kind = "upgraded" if compare(o, n) < 0 else "downgraded"
            result.changes.append(Change(eco, name, o, n, kind))
        else:
            for v in sorted(added):
                result.changes.append(Change(eco, name, None, v, "added"))
            for v in sorted(removed):
                result.changes.append(Change(eco, name, v, None, "removed"))
    return result
