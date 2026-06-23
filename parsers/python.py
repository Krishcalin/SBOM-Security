"""Python ecosystem parser — requirements.txt, poetry.lock, Pipfile.lock.

poetry.lock is TOML but parsed with a small regex so the tool needs no `toml`
dependency and works on Python 3.10 (which lacks `tomllib`). Only pinned versions
are emitted — an SBOM records what is actually resolved, not a range.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from core.models import Component
from parsers.base import BaseParser

# name==version  (also tolerates extras like name[extra]==version)
_REQ_PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([^\s;#\\]+)")
_POETRY_PKG = re.compile(r"\[\[package\]\]")
_KV = re.compile(r'^(name|version|category)\s*=\s*"([^"]*)"', re.MULTILINE)


class PythonParser(BaseParser):
    ECOSYSTEM = "pypi"
    PARSER_ID = "python"
    FILENAMES = ("requirements.txt", "poetry.lock", "Pipfile.lock")

    def matches(self, path: Path) -> bool:
        n = path.name
        return n in self.FILENAMES or (n.startswith("requirements") and n.endswith(".txt"))

    def parse(self, path: Path) -> list[Component]:
        text = path.read_text(encoding="utf-8", errors="ignore")
        if path.name == "poetry.lock":
            return self._poetry(text)
        if path.name == "Pipfile.lock":
            return self._pipfile(text)
        return self._requirements(text)

    def _requirements(self, text: str) -> list[Component]:
        out: list[Component] = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "-", "git+", "http")):
                continue
            m = _REQ_PIN.match(line)
            if m:
                out.append(Component(name=m.group(1), version=m.group(2),
                                     ecosystem=self.ECOSYSTEM, direct=True))
        return out

    def _poetry(self, text: str) -> list[Component]:
        out: list[Component] = []
        chunks = _POETRY_PKG.split(text)[1:]   # drop preamble before first [[package]]
        for chunk in chunks:
            fields = {k: v for k, v in _KV.findall(chunk)}
            name, version = fields.get("name"), fields.get("version")
            if name and version:
                scope = "dev" if fields.get("category") == "dev" else None
                out.append(Component(name=name, version=version,
                                     ecosystem=self.ECOSYSTEM, scope=scope))
        return out

    def _pipfile(self, text: str) -> list[Component]:
        out: list[Component] = []
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return out
        for section, scope, direct in (("default", "runtime", True), ("develop", "dev", True)):
            for name, spec in (data.get(section) or {}).items():
                version = ""
                if isinstance(spec, dict):
                    version = str(spec.get("version", "")).lstrip("=")
                if version:
                    out.append(Component(name=name, version=version, ecosystem=self.ECOSYSTEM,
                                         direct=direct, scope=scope))
        return out
