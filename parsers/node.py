"""Node ecosystem parser — package-lock.json (v1/v2/v3) and yarn.lock.

Lockfiles give exact resolved versions for the full transitive tree, which is
exactly what an SBOM wants. package-lock v2/v3 use the flat ``packages`` map; v1
uses the nested ``dependencies`` tree. yarn.lock is a custom format parsed line by
line.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from core.models import Component
from parsers.base import BaseParser

_YARN_VERSION = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?', re.MULTILINE)


class NodeParser(BaseParser):
    ECOSYSTEM = "npm"
    PARSER_ID = "node"
    FILENAMES = ("package-lock.json", "yarn.lock")

    def parse(self, path: Path) -> list[Component]:
        text = path.read_text(encoding="utf-8", errors="ignore")
        if path.name == "yarn.lock":
            return self._yarn(text)
        return self._npm_lock(text)

    def _npm_lock(self, text: str) -> list[Component]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []
        if "packages" in data:                       # lockfile v2/v3
            return self._npm_v2(data["packages"])
        return self._npm_v1(data.get("dependencies", {}))

    def _npm_v2(self, packages: dict) -> list[Component]:
        out: list[Component] = []
        for loc, info in packages.items():
            if not loc or not isinstance(info, dict):  # "" is the root project
                continue
            name = info.get("name") or loc.split("node_modules/")[-1]
            version = info.get("version", "")
            if name and version:
                # a single "node_modules/" segment => top-level (direct) install
                out.append(Component(name=name, version=version, ecosystem=self.ECOSYSTEM,
                                     direct=loc.count("node_modules/") == 1,
                                     scope="dev" if info.get("dev") else None))
        return out

    def _npm_v1(self, deps: dict, direct: bool = True) -> list[Component]:
        out: list[Component] = []
        for name, info in (deps or {}).items():
            if not isinstance(info, dict):
                continue
            version = info.get("version", "")
            if version:
                out.append(Component(name=name, version=version, ecosystem=self.ECOSYSTEM,
                                     direct=direct, scope="dev" if info.get("dev") else None))
            nested = info.get("dependencies")
            if nested:
                out.extend(self._npm_v1(nested, direct=False))
        return out

    def _yarn(self, text: str) -> list[Component]:
        out: list[Component] = []
        block: list[str] = []

        def flush(lines: list[str]) -> None:
            if not lines:
                return
            header = lines[0].strip().rstrip(":")
            spec = header.split(",")[0].strip().strip('"')
            name = self._yarn_name(spec)
            m = _YARN_VERSION.search("\n".join(lines[1:]))
            if name and m:
                out.append(Component(name=name, version=m.group(1), ecosystem=self.ECOSYSTEM))

        for line in text.splitlines():
            if line and not line[0].isspace() and not line.startswith("#"):
                flush(block)
                block = [line]
            elif block:
                block.append(line)
        flush(block)
        return out

    @staticmethod
    def _yarn_name(spec: str) -> str:
        # spec like "@scope/pkg@^1.0.0", "pkg@npm:1.2.3", "pkg@^1.0.0"
        if spec.startswith("@"):
            at = spec.find("@", 1)
            return spec[:at] if at != -1 else spec
        return spec.split("@", 1)[0]
