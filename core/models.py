"""Data models for the SBOM tool.

A Component is one resolved dependency; an Sbom is the set of components found in a
project. Models are ecosystem-agnostic — parsers translate manifests/lockfiles into
Components, and serializers (CycloneDX) translate Components out.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ComponentType(str, Enum):
    LIBRARY = "library"
    APPLICATION = "application"
    FRAMEWORK = "framework"
    OS = "operating-system"


@dataclass
class Component:
    name: str
    version: str
    ecosystem: str                       # pypi | npm | maven | golang
    type: str = ComponentType.LIBRARY.value
    purl: str = ""
    licenses: list[str] = field(default_factory=list)
    direct: bool | None = None           # direct dependency vs transitive (if known)
    scope: str | None = None             # runtime | dev | optional (if known)
    source: str = ""                     # manifest/lockfile it was found in

    def __post_init__(self) -> None:
        if not self.purl:
            from core.purl import build_purl
            self.purl = build_purl(self.ecosystem, self.name, self.version)

    @property
    def key(self) -> tuple[str, str, str]:
        """Identity for dedup: ecosystem + normalized name + version."""
        return (self.ecosystem, self.name.lower(), self.version)


@dataclass
class Sbom:
    root: str
    components: list[Component] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.components)

    def by_ecosystem(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for c in self.components:
            counts[c.ecosystem] = counts.get(c.ecosystem, 0) + 1
        return counts
