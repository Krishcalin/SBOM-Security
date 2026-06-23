"""Java ecosystem parser — Maven pom.xml and Gradle gradle.lockfile.

pom.xml: the project's *direct* dependencies under the top-level <dependencies>
(not <dependencyManagement>, which only declares versions). Simple `${property}`
references — including `${project.version}` — are resolved from <properties>.
Dependencies whose version can't be resolved (inherited from a parent/BOM) are
skipped, since an SBOM should record concrete versions.

gradle.lockfile: one resolved coordinate per line (`group:artifact:version=...`),
which is already exact.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from core.models import Component
from parsers.base import BaseParser

_PROP_REF = re.compile(r"\$\{([^}]+)\}")


def _local(tag: str) -> str:
    return tag.split("}", 1)[-1]   # strip the XML namespace


class MavenParser(BaseParser):
    ECOSYSTEM = "maven"
    PARSER_ID = "maven"
    FILENAMES = ("pom.xml", "gradle.lockfile")

    def parse(self, path: Path) -> list[Component]:
        if path.name == "gradle.lockfile":
            return self._gradle(path.read_text(encoding="utf-8", errors="ignore"))
        return self._pom(path.read_text(encoding="utf-8", errors="ignore"))

    def _pom(self, text: str) -> list[Component]:
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return []

        props: dict[str, str] = {}
        for child in root:
            tag = _local(child.tag)
            if tag == "properties":
                for prop in child:
                    props[_local(prop.tag)] = (prop.text or "").strip()
            elif tag == "version":
                props["project.version"] = (child.text or "").strip()
            elif tag == "groupId":
                props["project.groupId"] = (child.text or "").strip()

        out: list[Component] = []
        for child in root:
            if _local(child.tag) != "dependencies":
                continue
            for dep in child:
                if _local(dep.tag) != "dependency":
                    continue
                fields = {_local(c.tag): (c.text or "").strip() for c in dep}
                group, artifact = fields.get("groupId"), fields.get("artifactId")
                version = self._resolve(fields.get("version"), props)
                if not (group and artifact and version):
                    continue
                scope_raw = fields.get("scope")
                scope = "dev" if scope_raw == "test" else scope_raw
                out.append(Component(name=f"{group}:{artifact}", version=version,
                                     ecosystem=self.ECOSYSTEM, direct=True, scope=scope))
        return out

    @staticmethod
    def _resolve(value: str | None, props: dict[str, str]) -> str | None:
        if not value:
            return None
        m = _PROP_REF.fullmatch(value.strip())
        if m:
            return props.get(m.group(1))   # None if the property is unknown
        return value.strip()

    def _gradle(self, text: str) -> list[Component]:
        out: list[Component] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("empty="):
                continue
            coord = line.split("=", 1)[0]
            parts = coord.split(":")
            if len(parts) >= 3:
                group, artifact, version = parts[0], parts[1], parts[2]
                out.append(Component(name=f"{group}:{artifact}", version=version,
                                     ecosystem=self.ECOSYSTEM))
        return out
