"""Phase 3 tests — CVSS parsing, OSV client/audit (no network)."""

from __future__ import annotations

from core.cvss import base_score, severity_from_score
from core.cyclonedx import to_cyclonedx
from core.models import Component, Sbom, VulnSeverity
from core.osv import OSVClient, parse_vuln, run_audit

# A real-ish OSV advisory document (trimmed).
RAW_VULN = {
    "id": "GHSA-xxxx-yyyy-zzzz",
    "aliases": ["CVE-2024-9999"],
    "summary": "Remote code execution in example",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.1"}]}]}],
    "database_specific": {"severity": "HIGH"},
}


# ── CVSS ──────────────────────────────────────────────────────────────────
def test_cvss_critical_vector():
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8


def test_cvss_medium_vector():
    score = base_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N")
    assert 4.0 <= score < 7.0


def test_cvss_unparseable_returns_none():
    assert base_score("CVSS:4.0/AV:N") is None
    assert base_score("not a vector") is None


def test_severity_buckets():
    assert severity_from_score(9.8) == "critical"
    assert severity_from_score(7.0) == "high"
    assert severity_from_score(5.0) == "medium"
    assert severity_from_score(3.9) == "low"
    assert severity_from_score(0.0) == "none"
    assert severity_from_score(None) == "unknown"


# ── advisory parsing ───────────────────────────────────────────────────────
def test_parse_vuln_extracts_fields():
    v = parse_vuln(RAW_VULN)
    assert v.id == "CVE-2024-9999"                 # CVE alias preferred for display
    assert v.osv_id == "GHSA-xxxx-yyyy-zzzz"
    assert v.severity == VulnSeverity.CRITICAL and v.cvss == 9.8
    assert v.fixed == ["2.0.1"]
    assert v.reference.endswith("GHSA-xxxx-yyyy-zzzz")


def test_parse_vuln_falls_back_to_text_severity():
    raw = {"id": "OSV-1", "database_specific": {"severity": "MODERATE"}}
    assert parse_vuln(raw).severity == VulnSeverity.MEDIUM


# ── OSV client + audit (fake HTTP) ─────────────────────────────────────────
class _FakeClient:
    def __init__(self):
        self.fetched = []

    def query_batch(self, purls):
        return {"pkg:pypi/django@1.0": ["GHSA-xxxx-yyyy-zzzz"]}

    def fetch(self, vid):
        self.fetched.append(vid)
        return RAW_VULN


def test_query_batch_maps_purls_to_ids():
    def fake_post(url, payload, timeout):
        assert url.endswith("/v1/querybatch")
        return {"results": [{"vulns": [{"id": "GHSA-1"}]}, {}]}
    client = OSVClient(http_post=fake_post)
    mapping = client.query_batch(["pkg:pypi/a@1", "pkg:pypi/b@2"])
    assert mapping == {"pkg:pypi/a@1": ["GHSA-1"]}   # second purl had no vulns


def test_run_audit_attaches_and_caches():
    comps = [
        Component(name="django", version="1.0", ecosystem="pypi"),   # -> pkg:pypi/django@1.0
        Component(name="django", version="1.0", ecosystem="pypi", source="other"),
    ]
    client = _FakeClient()
    assert run_audit(comps, client) is True
    assert comps[0].vulnerabilities[0].id == "CVE-2024-9999"
    # same advisory id fetched only once despite two components
    assert client.fetched == ["GHSA-xxxx-yyyy-zzzz"]


def test_run_audit_offline_fails_safe():
    class Boom:
        def query_batch(self, purls):
            raise OSError("offline")
    comps = [Component(name="x", version="1", ecosystem="pypi")]
    assert run_audit(comps, Boom()) is False
    assert comps[0].vulnerabilities == []   # no false positives when offline


# ── CycloneDX vulnerabilities block ────────────────────────────────────────
def test_cyclonedx_includes_vulnerabilities():
    c = Component(name="django", version="1.0", ecosystem="pypi")
    c.vulnerabilities.append(parse_vuln(RAW_VULN))
    doc = to_cyclonedx(Sbom(root="p", components=[c]))
    assert "vulnerabilities" in doc
    vuln = doc["vulnerabilities"][0]
    assert vuln["id"] == "CVE-2024-9999"
    assert vuln["ratings"][0]["severity"] == "critical"
    assert vuln["affects"][0]["ref"] == "pkg:pypi/django@1.0"
