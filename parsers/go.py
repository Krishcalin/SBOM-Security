"""Go ecosystem parser — go.mod and go.sum.

go.mod's `require` directives are authoritative for the module set and mark
indirect (transitive) dependencies with a `// indirect` comment. go.sum adds any
remaining downloaded modules (its `/go.mod` version rows are de-suffixed). Versions
keep their leading `v` per the golang purl convention (pkg:golang/...@v1.2.3).
"""

from __future__ import annotations

from pathlib import Path

from core.models import Component
from parsers.base import BaseParser


class GoParser(BaseParser):
    ECOSYSTEM = "golang"
    PARSER_ID = "go"
    FILENAMES = ("go.mod", "go.sum")

    def parse(self, path: Path) -> list[Component]:
        text = path.read_text(encoding="utf-8", errors="ignore")
        return self._gosum(text) if path.name == "go.sum" else self._gomod(text)

    def _gomod(self, text: str) -> list[Component]:
        out: list[Component] = []
        in_block = False
        for raw in text.splitlines():
            line = raw.strip()
            if line.startswith("require ("):
                in_block = True
                continue
            if in_block and line == ")":
                in_block = False
                continue
            if in_block:
                comp = self._module(line)
            elif line.startswith("require "):
                comp = self._module(line[len("require "):])
            else:
                comp = None
            if comp:
                out.append(comp)
        return out

    def _module(self, spec: str) -> Component | None:
        indirect = "// indirect" in spec
        spec = spec.split("//", 1)[0].strip()
        parts = spec.split()
        if len(parts) >= 2:
            return Component(name=parts[0], version=parts[1], ecosystem=self.ECOSYSTEM,
                             direct=not indirect)
        return None

    def _gosum(self, text: str) -> list[Component]:
        out: list[Component] = []
        seen: set[tuple[str, str]] = set()
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            name, version = parts[0], parts[1]
            if version.endswith("/go.mod"):
                version = version[: -len("/go.mod")]
            if (name, version) in seen:
                continue
            seen.add((name, version))
            out.append(Component(name=name, version=version, ecosystem=self.ECOSYSTEM))
        return out
