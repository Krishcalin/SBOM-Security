"""SBOM generation engine — walk a project, dispatch files to parsers, dedup.

Vendored/dependency directories (node_modules, .venv, …) are skipped so the SBOM
reflects the project's *declared* dependencies (from its own lockfiles) rather than
re-ingesting every nested package's manifest.
"""

from __future__ import annotations

from pathlib import Path

from core.logger import get_logger
from core.models import Component, Sbom
from parsers.base import BaseParser

log = get_logger("engine")

_SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "__pycache__",
    "dist", "build", ".eggs", ".tox", ".gradle", "target", "vendor", ".idea", ".vscode",
}


def default_parsers() -> list[BaseParser]:
    from parsers.node import NodeParser
    from parsers.python import PythonParser
    return [PythonParser(), NodeParser()]


class SbomGenerator:
    def __init__(self, parsers: list[BaseParser] | None = None) -> None:
        self.parsers = parsers if parsers is not None else default_parsers()

    def generate(self, root: str | Path) -> Sbom:
        components: dict[tuple, Component] = {}
        for path in self._walk(root):
            for parser in self.parsers:
                if not parser.matches(path):
                    continue
                try:
                    found = parser.parse(path)
                except Exception as exc:  # a broken file must not abort the scan
                    log.warning("parse_failed", parser=parser.PARSER_ID,
                                path=str(path), error=str(exc))
                    continue
                for comp in found:
                    comp.source = str(path)
                    components.setdefault(comp.key, comp)
        ordered = sorted(components.values(),
                         key=lambda c: (c.ecosystem, c.name.lower(), c.version))
        return Sbom(root=str(root), components=ordered)

    def _walk(self, root: str | Path):
        root = Path(root)
        if root.is_file():
            yield root
            return
        for path in root.rglob("*"):
            if path.is_dir():
                continue
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            yield path
