"""Package URL (purl) construction — the stable cross-ecosystem component id.

A purl (https://github.com/package-url/purl-spec) like ``pkg:pypi/requests@2.31.0``
uniquely identifies a package across tools and is what vulnerability databases
(OSV, GitHub Advisories) key on. Building correct purls in Phase 1 means the
Phase 3 vulnerability correlation works without rework.
"""

from __future__ import annotations

import re
from urllib.parse import quote

_PYPI_NORM = re.compile(r"[-_.]+")


def _enc(value: str, safe: str = "") -> str:
    return quote(value, safe=safe)


def build_purl(ecosystem: str, name: str, version: str) -> str:
    """Build a purl for a component. Ecosystem is one of pypi|npm|maven|golang."""
    ver = f"@{_enc(version)}" if version else ""

    if ecosystem == "npm":
        if name.startswith("@") and "/" in name:                  # scoped: @scope/pkg
            scope, pkg = name[1:].split("/", 1)
            return f"pkg:npm/%40{_enc(scope)}/{_enc(pkg)}{ver}"
        return f"pkg:npm/{_enc(name)}{ver}"

    if ecosystem == "maven":
        if ":" in name:                                           # group:artifact
            group, artifact = name.split(":", 1)
            return f"pkg:maven/{_enc(group)}/{_enc(artifact)}{ver}"
        return f"pkg:maven/{_enc(name)}{ver}"

    if ecosystem == "golang":
        # module paths keep their slashes
        return f"pkg:golang/{_enc(name, safe='/')}{ver}"

    # pypi (default) — normalize per PEP 503: lowercase, runs of -_. collapse to -
    norm = _PYPI_NORM.sub("-", name).lower()
    return f"pkg:pypi/{_enc(norm)}{ver}"
