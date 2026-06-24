"""Baseline snapshot — accept the current state so scans flag only what's new.

A baseline captures the components present at a point in time plus the set of
vulnerability identifiers already known/acknowledged. Later runs use it two ways:

  - `drift` diffs the current components against the baseline's components.
  - `audit --baseline` reports only vulnerabilities whose id/alias is *not* in the
    baseline — i.e. newly-introduced ones — so accepted risk stays quiet.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from core.models import Component, Sbom


@dataclass
class Baseline:
    components: list[tuple[str, str, str]] = field(default_factory=list)  # (eco, name, version)
    vulnerabilities: set[str] = field(default_factory=set)               # ids + aliases

    @classmethod
    def from_sbom(cls, sbom: Sbom) -> "Baseline":
        comps = [(c.ecosystem, c.name, c.version) for c in sbom.components]
        vulns: set[str] = set()
        for c in sbom.components:
            for v in c.vulnerabilities:
                vulns.update({v.id, v.osv_id, *v.aliases})
        vulns.discard("")
        return cls(components=comps, vulnerabilities=vulns)

    @classmethod
    def load(cls, path: str | Path) -> "Baseline":
        data = json.loads(Path(path).read_text(encoding="utf-8")) or {}
        comps = [(c["ecosystem"], c["name"], c["version"]) for c in data.get("components", [])]
        return cls(components=comps, vulnerabilities=set(data.get("vulnerabilities", [])))

    def write(self, path: str | Path) -> Path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "component_count": len(self.components),
            "components": [{"ecosystem": e, "name": n, "version": v}
                           for e, n, v in sorted(self.components)],
            "vulnerabilities": sorted(self.vulnerabilities),
        }
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return out

    def as_components(self) -> list[Component]:
        return [Component(name=n, version=v, ecosystem=e) for e, n, v in self.components]

    def knows_vuln(self, vuln) -> bool:
        return bool({vuln.id, vuln.osv_id, *vuln.aliases} & self.vulnerabilities)
