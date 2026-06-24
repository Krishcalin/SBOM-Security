"""Phase 4 tests — version compare, drift diff, baseline."""

from __future__ import annotations

from core.baseline import Baseline
from core.drift import diff
from core.models import Component, Sbom, Vulnerability, VulnSeverity
from core.version import compare


# ── version comparison ──────────────────────────────────────────────────────
def test_compare_numeric_segments():
    assert compare("1.0.0", "1.0.1") == -1
    assert compare("2.0", "10.0") == -1          # numeric, not lexical
    assert compare("1.2.0", "1.2.0") == 0
    assert compare("3.0.0", "2.9.9") == 1


def test_compare_strips_v_prefix_and_prerelease():
    assert compare("v1.2.3", "1.2.3") == 0
    assert compare("1.0.0-rc1", "1.0.0") == -1   # pre-release < release
    assert compare("1.0.0+build", "1.0.0") == 0  # build metadata ignored


# ── drift ────────────────────────────────────────────────────────────────────
def _c(name, version, eco="pypi"):
    return Component(name=name, version=version, ecosystem=eco)


def test_diff_detects_all_kinds():
    old = [_c("requests", "2.30.0"), _c("flask", "3.0.0"), _c("click", "8.1.0")]
    new = [_c("requests", "2.31.0"), _c("flask", "2.9.0"), _c("rich", "13.0.0")]
    result = diff(old, new)
    kinds = {(c.name, c.kind) for c in result.changes}
    assert ("requests", "upgraded") in kinds     # 2.30 -> 2.31
    assert ("flask", "downgraded") in kinds       # 3.0 -> 2.9
    assert ("click", "removed") in kinds
    assert ("rich", "added") in kinds


def test_diff_no_changes():
    comps = [_c("requests", "2.31.0")]
    result = diff(comps, list(comps))
    assert not result.has_changes and result.unchanged == 1


def test_diff_counts_by_kind():
    old = [_c("a", "1.0")]
    new = [_c("a", "1.1"), _c("b", "1.0")]
    counts = diff(old, new).by_kind()
    assert counts == {"upgraded": 1, "added": 1}


# ── baseline ─────────────────────────────────────────────────────────────────
def _sbom_with_vuln():
    c = _c("django", "1.0")
    c.vulnerabilities.append(Vulnerability(id="CVE-2024-1", osv_id="GHSA-aaa",
                                           aliases=["CVE-2024-1"], severity=VulnSeverity.HIGH))
    return Sbom(root="p", components=[c, _c("requests", "2.31.0")])


def test_baseline_roundtrip_and_diff(tmp_path):
    base = Baseline.from_sbom(_sbom_with_vuln())
    path = base.write(tmp_path / "bl.json")
    loaded = Baseline.load(path)
    assert ("pypi", "django", "1.0") in loaded.components
    # diff a changed project against the baseline
    new = [_c("django", "1.1"), _c("requests", "2.31.0")]
    result = diff(loaded.as_components(), new)
    assert any(c.name == "django" and c.kind == "upgraded" for c in result.changes)


def test_baseline_knows_vuln_by_any_identifier(tmp_path):
    base = Baseline.from_sbom(_sbom_with_vuln())
    base = Baseline.load(base.write(tmp_path / "bl.json"))
    known = Vulnerability(id="CVE-2024-1", osv_id="GHSA-aaa", aliases=["CVE-2024-1"])
    fresh = Vulnerability(id="CVE-2025-9", osv_id="GHSA-zzz", aliases=["CVE-2025-9"])
    assert base.knows_vuln(known) is True
    assert base.knows_vuln(fresh) is False
