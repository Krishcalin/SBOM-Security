"""Phase 6 tests — compliance mapping and reporting."""

from __future__ import annotations

import json

import pytest

from core.compliance import framework_summary, ntia_minimum_elements
from core.models import Component, Sbom, Vulnerability, VulnSeverity
from core.policy import Violation
from core.reporter import result_to_dict, to_csv, to_html, write_report


def _sbom():
    a = Component(name="django", version="1.0", ecosystem="pypi", licenses=["BSD-3-Clause"],
                  direct=True)
    a.vulnerabilities.append(Vulnerability(id="CVE-2024-1", severity=VulnSeverity.CRITICAL, cvss=9.8))
    b = Component(name="requests", version="2.31.0", ecosystem="pypi", direct=True)  # no license
    return Sbom(root="proj", components=[a, b])


# ── compliance ───────────────────────────────────────────────────────────────
def test_ntia_elements_status():
    elems = {e.element: e.status for e in ntia_minimum_elements(_sbom())}
    assert elems["Component version"] == "pass"          # all have versions
    assert elems["Unique identifiers (purl)"] == "pass"   # all have purls
    assert elems["License (extended element)"] == "partial"  # only 1 of 2 has a license


def test_framework_summary_vuln_status_tracks_audited():
    sbom = _sbom()
    scvs = {c["id"]: c["status"] for c in
            framework_summary(sbom, audited=True, policy_evaluated=False)["frameworks"]["OWASP SCVS"]}
    assert scvs["V5.10"] == "pass"
    scvs_no = {c["id"]: c["status"] for c in
               framework_summary(sbom, audited=False, policy_evaluated=False)["frameworks"]["OWASP SCVS"]}
    assert scvs_no["V5.10"] == "todo"


# ── reporting ────────────────────────────────────────────────────────────────
def test_result_to_dict_bundles_everything():
    v = [Violation("license", "error", "x@1 (pypi)", "denied")]
    d = result_to_dict(_sbom(), violations=v, audited=True)
    assert d["components"] == 2 and len(d["vulnerabilities"]) == 1
    assert d["policy_violations"][0]["kind"] == "license"
    assert "compliance" in d and d["compliance"]["audited"] is True


def test_csv_has_header_and_rows():
    lines = to_csv(_sbom()).strip().splitlines()
    assert lines[0].startswith("ecosystem,name,version,purl")
    assert any("django" in ln and "critical" in ln for ln in lines)


def test_html_escapes_and_includes_sections():
    sbom = _sbom()
    sbom.components[0].name = "<script>evil"   # the vulnerable component (shown in vulns table)
    out = to_html(sbom, audited=True)
    assert "SBOM Security Report" in out
    assert "NTIA Minimum Elements" in out and "OWASP SCVS" in out
    assert "&lt;script&gt;evil" in out and "<script>evil" not in out


def test_write_report_dispatch_and_unknown(tmp_path):
    sbom = _sbom()
    for ext in ("json", "csv", "html"):
        out = write_report(tmp_path / f"r.{ext}", sbom, audited=True)
        assert out.exists() and out.read_text(encoding="utf-8")
    data = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert data["components"] == 2
    with pytest.raises(ValueError):
        write_report(tmp_path / "r.txt", sbom)
