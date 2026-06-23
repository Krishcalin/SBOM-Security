"""CycloneDX 1.5 JSON serialization.

CycloneDX is the OWASP SBOM standard with first-class support for vulnerabilities
and VEX, which is why it's the primary format here — Phase 3 vulnerability
correlation will attach a `vulnerabilities` array to this same document.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from core import __version__
from core.models import Component, Sbom

SPEC_VERSION = "1.5"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _component_json(c: Component) -> dict:
    out: dict = {
        "type": c.type,
        "name": c.name,
        "version": c.version,
        "purl": c.purl,
        "bom-ref": c.purl or f"{c.name}@{c.version}",
    }
    if c.licenses:
        out["licenses"] = [{"license": {"name": lic}} for lic in c.licenses]
    props = [{"name": "ecosystem", "value": c.ecosystem}]
    if c.direct is not None:
        props.append({"name": "direct", "value": str(c.direct).lower()})
    if c.scope:
        props.append({"name": "scope", "value": c.scope})
    if c.source:
        props.append({"name": "source", "value": c.source})
    out["properties"] = props
    return out


def _bom_ref(c: Component) -> str:
    return c.purl or f"{c.name}@{c.version}"


def _vulnerabilities_json(sbom: Sbom) -> list[dict]:
    out: list[dict] = []
    for c in sbom.components:
        for v in c.vulnerabilities:
            rating: dict = {"severity": v.severity.value}
            if v.cvss is not None:
                rating |= {"method": "CVSSv3", "score": v.cvss}
            entry = {
                "bom-ref": f"{v.id}/{_bom_ref(c)}",
                "id": v.id,
                "source": {"name": "OSV", "url": v.reference},
                "ratings": [rating],
                "affects": [{"ref": _bom_ref(c)}],
            }
            if v.summary:
                entry["description"] = v.summary
            out.append(entry)
    return out


def to_cyclonedx(sbom: Sbom, app_name: str | None = None) -> dict:
    name = app_name or Path(sbom.root).resolve().name or "root"
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _now_iso(),
            "tools": [{"vendor": "KIZEN", "name": "sbom-security", "version": __version__}],
            "component": {"type": "application", "name": name, "version": "0.0.0",
                          "bom-ref": name},
        },
        "components": [_component_json(c) for c in sbom.components],
    }
    vulns = _vulnerabilities_json(sbom)
    if vulns:
        doc["vulnerabilities"] = vulns
    return doc


def dumps(sbom: Sbom, app_name: str | None = None) -> str:
    return json.dumps(to_cyclonedx(sbom, app_name=app_name), indent=2)
