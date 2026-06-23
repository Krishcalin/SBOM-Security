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


class VulnSeverity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


# ordering for --fail-on gates (UNKNOWN sorts low so it won't trip high/critical gates)
SEVERITY_ORDER = {
    VulnSeverity.UNKNOWN: 0, VulnSeverity.NONE: 0, VulnSeverity.LOW: 1,
    VulnSeverity.MEDIUM: 2, VulnSeverity.HIGH: 3, VulnSeverity.CRITICAL: 4,
}


@dataclass
class Vulnerability:
    id: str                              # display id (CVE preferred, else OSV id)
    osv_id: str = ""                     # original OSV id (GHSA-…/PYSEC-…)
    aliases: list[str] = field(default_factory=list)
    summary: str = ""
    severity: VulnSeverity = VulnSeverity.UNKNOWN
    cvss: float | None = None
    fixed: list[str] = field(default_factory=list)
    reference: str = ""


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
    vulnerabilities: list = field(default_factory=list)  # list[Vulnerability], populated by audit

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
