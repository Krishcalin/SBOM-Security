"""SPDX 2.3 JSON serialization.

SPDX is the ISO/Linux-Foundation SBOM standard, often required in procurement and
license-compliance contexts. Each component becomes an SPDX package with a purl
external reference; the document DESCRIBES the root and the root DEPENDS_ON each
package. Package SPDXIDs are index-based to guarantee the spec's ID charset.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from core import __version__
from core.models import Component, Sbom


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _license(c: Component) -> str:
    return " AND ".join(c.licenses) if c.licenses else "NOASSERTION"


def _package(c: Component, spdxid: str) -> dict:
    return {
        "name": c.name,
        "SPDXID": spdxid,
        "versionInfo": c.version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": _license(c),
        "externalRefs": [{
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": c.purl,
        }],
    }


def to_spdx(sbom: Sbom, app_name: str | None = None) -> dict:
    name = app_name or Path(sbom.root).resolve().name or "root"
    packages, relationships = [], []
    for i, comp in enumerate(sbom.components, start=1):
        spdxid = f"SPDXRef-Package-{i}"
        packages.append(_package(comp, spdxid))
        relationships.append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relatedSpdxElement": spdxid,
            "relationshipType": "DEPENDS_ON",
        })
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": name,
        "documentNamespace": f"https://kizen.dev/spdx/{name}-{uuid4()}",
        "creationInfo": {
            "created": _now_iso(),
            "creators": [f"Tool: sbom-security-{__version__}"],
        },
        "packages": packages,
        "relationships": relationships,
    }


def dumps(sbom: Sbom, app_name: str | None = None) -> str:
    return json.dumps(to_spdx(sbom, app_name=app_name), indent=2)
