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


def to_cyclonedx(sbom: Sbom, app_name: str | None = None) -> dict:
    name = app_name or Path(sbom.root).resolve().name or "root"
    return {
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


def dumps(sbom: Sbom, app_name: str | None = None) -> str:
    return json.dumps(to_cyclonedx(sbom, app_name=app_name), indent=2)
