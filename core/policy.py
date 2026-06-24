"""Policy & compliance — evaluate an SBOM against an organization's rules.

A YAML policy declares which licenses are allowed/denied, which packages are
banned, and the maximum tolerated vulnerability severity. `Policy.evaluate()`
returns `Violation`s (error or warn); the `check` CLI fails the build on any error.
This is where the SPDX license IDs (Phase 2) and CVSS severities (Phase 3) become
enforceable gates.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from core.models import SEVERITY_ORDER, Sbom, VulnSeverity

_UNKNOWN_MODES = {"allow", "warn", "deny"}


@dataclass
class Violation:
    kind: str          # license | unknown_license | banned_package | vulnerability
    level: str         # error | warn
    component: str     # "name@version (ecosystem)"
    detail: str
    purl: str = ""


@dataclass
class Policy:
    license_allow: list[str] = field(default_factory=list)   # allowlist (empty = not enforced)
    license_deny: list[str] = field(default_factory=list)
    license_unknown: str = "allow"                           # allow | warn | deny
    banned_packages: list[dict] = field(default_factory=list)
    max_vuln_severity: str | None = None                     # tolerate up to this; above = violation

    @classmethod
    def default(cls) -> "Policy":
        return cls()

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        lic = data.get("licenses", {}) or {}
        unknown = str(lic.get("unknown", "allow")).lower()
        vulns = data.get("vulnerabilities", {}) or {}
        sev = vulns.get("max_severity")
        return cls(
            license_allow=[str(x) for x in (lic.get("allow") or [])],
            license_deny=[str(x) for x in (lic.get("deny") or [])],
            license_unknown=unknown if unknown in _UNKNOWN_MODES else "allow",
            banned_packages=list(data.get("banned_packages") or []),
            max_vuln_severity=str(sev).lower() if sev else None,
        )

    @property
    def needs_audit(self) -> bool:
        return self.max_vuln_severity is not None

    def evaluate(self, sbom: Sbom) -> list[Violation]:
        out: list[Violation] = []
        for c in sbom.components:
            who = f"{c.name}@{c.version} ({c.ecosystem})"
            out.extend(self._license(c, who))
            out.extend(self._banned(c, who))
            out.extend(self._vulns(c, who))
        out.sort(key=lambda v: (v.level != "error", v.kind))
        return out

    # ── individual checks ────────────────────────────────────────────────
    def _license(self, c, who: str) -> list[Violation]:
        if not c.licenses:
            if self.license_unknown == "allow":
                return []
            level = "error" if self.license_unknown == "deny" else "warn"
            return [Violation("unknown_license", level, who, "no license metadata", c.purl)]

        found = [lic.lower() for lic in c.licenses]
        out: list[Violation] = []
        if self.license_deny:
            denied = {d.lower() for d in self.license_deny}
            hits = [lic for lic in c.licenses if lic.lower() in denied]
            if hits:
                out.append(Violation("license", "error", who,
                                     f"denied license: {', '.join(hits)}", c.purl))
        if self.license_allow:
            allowed = {a.lower() for a in self.license_allow}
            if not any(lic in allowed for lic in found):
                out.append(Violation("license", "error", who,
                                     f"license not in allowlist: {', '.join(c.licenses)}", c.purl))
        return out

    def _banned(self, c, who: str) -> list[Violation]:
        for rule in self.banned_packages:
            if str(rule.get("name", "")).lower() != c.name.lower():
                continue
            if rule.get("ecosystem") and rule["ecosystem"] != c.ecosystem:
                continue
            if rule.get("version") and str(rule["version"]) != c.version:
                continue
            reason = rule.get("reason", "banned package")
            return [Violation("banned_package", "error", who, str(reason), c.purl)]
        return []

    def _vulns(self, c, who: str) -> list[Violation]:
        if not self.max_vuln_severity:
            return []
        try:
            ceiling = SEVERITY_ORDER[VulnSeverity(self.max_vuln_severity)]
        except (KeyError, ValueError):
            return []
        out: list[Violation] = []
        for v in c.vulnerabilities:
            if SEVERITY_ORDER.get(v.severity, 0) > ceiling:
                cvss = f" cvss {v.cvss}" if v.cvss is not None else ""
                out.append(Violation("vulnerability", "error", who,
                                     f"{v.id} {v.severity.value}{cvss} > max {self.max_vuln_severity}",
                                     c.purl))
        return out
