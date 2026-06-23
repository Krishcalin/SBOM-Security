"""Phase 1 tests — purl, parsers, engine, CycloneDX."""

from __future__ import annotations

from core.cyclonedx import to_cyclonedx
from core.engine import SbomGenerator
from core.purl import build_purl
from parsers.node import NodeParser
from parsers.python import PythonParser


# ── purl ──────────────────────────────────────────────────────────────────
def test_purl_pypi_normalizes_name():
    assert build_purl("pypi", "Flask_Cors", "4.0.0") == "pkg:pypi/flask-cors@4.0.0"


def test_purl_npm_scoped():
    assert build_purl("npm", "@scope/pkg", "1.2.3") == "pkg:npm/%40scope/pkg@1.2.3"


def test_purl_maven_group_artifact():
    assert build_purl("maven", "org.apache:commons", "1.0") == "pkg:maven/org.apache/commons@1.0"


def test_purl_golang_keeps_slashes():
    assert build_purl("golang", "github.com/pkg/errors", "0.9.1") == \
        "pkg:golang/github.com/pkg/errors@0.9.1"


# ── Python parser ───────────────────────────────────────────────────────────
def test_requirements_parses_pinned_only(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("# comment\nrequests==2.31.0\nflask>=2.0\n-e .\nclick[extra]==8.1.7\n",
                 encoding="utf-8")
    comps = {c.name: c.version for c in PythonParser().parse(f)}
    assert comps == {"requests": "2.31.0", "click": "8.1.7"}  # flask (range) and -e skipped


def test_poetry_lock_parses_packages(tmp_path):
    f = tmp_path / "poetry.lock"
    f.write_text(
        '[[package]]\nname = "requests"\nversion = "2.31.0"\ncategory = "main"\n\n'
        '[[package]]\nname = "pytest"\nversion = "7.4.0"\ncategory = "dev"\n',
        encoding="utf-8")
    comps = {c.name: (c.version, c.scope) for c in PythonParser().parse(f)}
    assert comps["requests"] == ("2.31.0", None)
    assert comps["pytest"] == ("7.4.0", "dev")


def test_pipfile_lock_parses_sections(tmp_path):
    f = tmp_path / "Pipfile.lock"
    f.write_text('{"default":{"requests":{"version":"==2.31.0"}},'
                 '"develop":{"pytest":{"version":"==7.4.0"}}}', encoding="utf-8")
    comps = {c.name: (c.version, c.scope) for c in PythonParser().parse(f)}
    assert comps["requests"] == ("2.31.0", "runtime")
    assert comps["pytest"] == ("7.4.0", "dev")


# ── Node parser ─────────────────────────────────────────────────────────────
def test_npm_lock_v3_packages(tmp_path):
    f = tmp_path / "package-lock.json"
    f.write_text('{"name":"app","lockfileVersion":3,"packages":{'
                 '"":{"name":"app"},'
                 '"node_modules/lodash":{"version":"4.17.21"},'
                 '"node_modules/lodash/node_modules/foo":{"version":"1.0.0"}}}',
                 encoding="utf-8")
    comps = {c.name: (c.version, c.direct) for c in NodeParser().parse(f)}
    assert comps["lodash"] == ("4.17.21", True)
    assert comps["foo"] == ("1.0.0", False)   # nested => transitive


def test_npm_lock_v1_nested(tmp_path):
    f = tmp_path / "package-lock.json"
    f.write_text('{"name":"app","dependencies":{"lodash":{"version":"4.17.21",'
                 '"dependencies":{"foo":{"version":"1.0.0"}}}}}', encoding="utf-8")
    comps = {c.name: c.version for c in NodeParser().parse(f)}
    assert comps == {"lodash": "4.17.21", "foo": "1.0.0"}


def test_yarn_lock(tmp_path):
    f = tmp_path / "yarn.lock"
    f.write_text('# yarn lockfile v1\n\n'
                 'lodash@^4.17.0:\n  version "4.17.21"\n  resolved "x"\n\n'
                 '"@scope/pkg@^1.0.0":\n  version "1.2.3"\n', encoding="utf-8")
    comps = {c.name: c.version for c in NodeParser().parse(f)}
    assert comps == {"lodash": "4.17.21", "@scope/pkg": "1.2.3"}


# ── engine ──────────────────────────────────────────────────────────────────
def test_engine_mixes_ecosystems_and_skips_node_modules(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(
        '{"packages":{"node_modules/lodash":{"version":"4.17.21"}}}', encoding="utf-8")
    nm = tmp_path / "node_modules" / "evil"
    nm.mkdir(parents=True)
    (nm / "package-lock.json").write_text(
        '{"packages":{"node_modules/should_not_appear":{"version":"9.9.9"}}}', encoding="utf-8")

    sbom = SbomGenerator().generate(tmp_path)
    names = {c.name for c in sbom.components}
    assert "requests" in names and "lodash" in names
    assert "should_not_appear" not in names         # node_modules walked-over
    assert sbom.by_ecosystem() == {"npm": 1, "pypi": 1}


def test_engine_dedups_same_component(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    (tmp_path / "requirements-dev.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    sbom = SbomGenerator().generate(tmp_path)
    assert sum(c.name == "requests" for c in sbom.components) == 1


# ── CycloneDX ────────────────────────────────────────────────────────────────
def test_cyclonedx_structure(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    sbom = SbomGenerator().generate(tmp_path)
    doc = to_cyclonedx(sbom, app_name="demo")
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.5"
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert doc["metadata"]["component"]["name"] == "demo"
    comp = doc["components"][0]
    assert comp["purl"] == "pkg:pypi/requests@2.31.0" and comp["type"] == "library"
