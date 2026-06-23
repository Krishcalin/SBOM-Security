"""Phase 2 tests — Maven & Go parsers, license normalization, SPDX export."""

from __future__ import annotations

from core.engine import SbomGenerator
from core.licenses import normalize_spdx
from core.models import Sbom
from core.spdx import to_spdx
from parsers.go import GoParser
from parsers.maven import MavenParser
from parsers.node import NodeParser

POM = """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <version>1.0.0</version>
  <properties>
    <junit.version>5.10.0</junit.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>32.1.3-jre</version>
    </dependency>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <version>${junit.version}</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>no.version</groupId>
      <artifactId>inherited</artifactId>
    </dependency>
  </dependencies>
</project>
"""


# ── Maven ──────────────────────────────────────────────────────────────────
def test_pom_resolves_properties_and_scope_skips_unversioned(tmp_path):
    f = tmp_path / "pom.xml"
    f.write_text(POM, encoding="utf-8")
    comps = {c.name: (c.version, c.scope) for c in MavenParser().parse(f)}
    assert comps["com.google.guava:guava"] == ("32.1.3-jre", None)
    assert comps["org.junit.jupiter:junit-jupiter"] == ("5.10.0", "dev")  # ${junit.version}, test->dev
    assert "no.version:inherited" not in comps                            # unresolved version skipped


def test_pom_purl_is_maven(tmp_path):
    f = tmp_path / "pom.xml"
    f.write_text(POM, encoding="utf-8")
    guava = next(c for c in MavenParser().parse(f) if "guava" in c.name)
    assert guava.purl == "pkg:maven/com.google.guava/guava@32.1.3-jre"


def test_gradle_lockfile(tmp_path):
    f = tmp_path / "gradle.lockfile"
    f.write_text("# gradle lockfile\n"
                 "com.squareup.okhttp3:okhttp:4.12.0=runtimeClasspath\n"
                 "empty=annotationProcessor\n", encoding="utf-8")
    comps = [c for c in MavenParser().parse(f)]
    assert len(comps) == 1
    assert comps[0].name == "com.squareup.okhttp3:okhttp" and comps[0].version == "4.12.0"


# ── Go ──────────────────────────────────────────────────────────────────────
def test_gomod_block_and_indirect(tmp_path):
    f = tmp_path / "go.mod"
    f.write_text(
        "module example.com/app\n\ngo 1.21\n\n"
        "require github.com/gorilla/mux v1.8.0\n\n"
        "require (\n\tgithub.com/pkg/errors v0.9.1\n\tgolang.org/x/sys v0.15.0 // indirect\n)\n",
        encoding="utf-8")
    comps = {c.name: (c.version, c.direct) for c in GoParser().parse(f)}
    assert comps["github.com/gorilla/mux"] == ("v1.8.0", True)
    assert comps["github.com/pkg/errors"] == ("v0.9.1", True)
    assert comps["golang.org/x/sys"] == ("v0.15.0", False)


def test_gomod_purl_keeps_v(tmp_path):
    f = tmp_path / "go.mod"
    f.write_text("require github.com/pkg/errors v0.9.1\n", encoding="utf-8")
    c = GoParser().parse(f)[0]
    assert c.purl == "pkg:golang/github.com/pkg/errors@v0.9.1"


def test_gosum_strips_gomod_suffix_and_dedups(tmp_path):
    f = tmp_path / "go.sum"
    f.write_text(
        "github.com/pkg/errors v0.9.1 h1:abc=\n"
        "github.com/pkg/errors v0.9.1/go.mod h1:def=\n", encoding="utf-8")
    comps = GoParser().parse(f)
    assert len(comps) == 1 and comps[0].version == "v0.9.1"


# ── licenses ─────────────────────────────────────────────────────────────────
def test_license_normalization():
    assert normalize_spdx("Apache License, Version 2.0") == "Apache-2.0"
    assert normalize_spdx("MIT License") == "MIT"
    assert normalize_spdx("Weird Custom") == "Weird Custom"   # unknown passes through
    assert normalize_spdx(None) == ""


def test_node_extracts_license(tmp_path):
    f = tmp_path / "package-lock.json"
    f.write_text('{"packages":{"node_modules/lodash":{"version":"4.17.21","license":"MIT"}}}',
                 encoding="utf-8")
    c = NodeParser().parse(f)[0]
    assert c.licenses == ["MIT"]


# ── engine merge + SPDX ──────────────────────────────────────────────────────
def test_engine_merge_prefers_direct_flag(tmp_path):
    # go.sum (direct unknown) + go.mod (direct known) for the same module
    (tmp_path / "go.mod").write_text("require github.com/pkg/errors v0.9.1\n", encoding="utf-8")
    (tmp_path / "go.sum").write_text("github.com/pkg/errors v0.9.1 h1:x=\n", encoding="utf-8")
    sbom = SbomGenerator().generate(tmp_path)
    errs = [c for c in sbom.components if c.name == "github.com/pkg/errors"]
    assert len(errs) == 1 and errs[0].direct is True


def test_spdx_export_structure(tmp_path):
    from core.models import Component
    sbom = Sbom(root="proj", components=[
        Component(name="requests", version="2.31.0", ecosystem="pypi", licenses=["MIT"]),
    ])
    doc = to_spdx(sbom, app_name="demo")
    assert doc["spdxVersion"] == "SPDX-2.3" and doc["SPDXID"] == "SPDXRef-DOCUMENT"
    pkg = doc["packages"][0]
    assert pkg["SPDXID"] == "SPDXRef-Package-1" and pkg["versionInfo"] == "2.31.0"
    assert pkg["licenseDeclared"] == "MIT"
    assert pkg["externalRefs"][0]["referenceLocator"] == "pkg:pypi/requests@2.31.0"
    assert doc["relationships"][0]["relationshipType"] == "DEPENDS_ON"
