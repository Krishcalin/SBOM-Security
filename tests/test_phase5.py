"""Phase 5 tests — policy & license compliance."""

from __future__ import annotations

from core.models import Component, Sbom, Vulnerability, VulnSeverity
from core.policy import Policy


def _sbom(components):
    return Sbom(root="p", components=components)


def _c(name, version="1.0", eco="pypi", licenses=None):
    return Component(name=name, version=version, ecosystem=eco, licenses=licenses or [])


# ── defaults ────────────────────────────────────────────────────────────────
def test_default_policy_is_permissive():
    sbom = _sbom([_c("requests", licenses=["MIT"]), _c("nolicense")])
    assert Policy.default().evaluate(sbom) == []


# ── licenses ────────────────────────────────────────────────────────────────
def test_denied_license_is_error():
    pol = Policy(license_deny=["GPL-3.0-only"])
    v = pol.evaluate(_sbom([_c("copyleft", licenses=["GPL-3.0-only"])]))
    assert len(v) == 1 and v[0].kind == "license" and v[0].level == "error"


def test_allowlist_blocks_other_licenses():
    pol = Policy(license_allow=["MIT", "Apache-2.0"])
    sbom = _sbom([_c("ok", licenses=["MIT"]), _c("bad", licenses=["BSD-3-Clause"])])
    kinds = [(x.component, x.kind) for x in pol.evaluate(sbom)]
    assert any("bad" in comp for comp, _ in kinds)
    assert not any("ok@" in comp for comp, _ in kinds)


def test_unknown_license_modes():
    sbom = _sbom([_c("mystery")])
    assert Policy(license_unknown="allow").evaluate(sbom) == []
    warn = Policy(license_unknown="warn").evaluate(sbom)
    assert warn and warn[0].level == "warn" and warn[0].kind == "unknown_license"
    deny = Policy(license_unknown="deny").evaluate(sbom)
    assert deny and deny[0].level == "error"


# ── banned packages ──────────────────────────────────────────────────────────
def test_banned_package_by_name_and_ecosystem():
    pol = Policy(banned_packages=[{"name": "event-stream", "ecosystem": "npm",
                                   "reason": "malicious"}])
    sbom = _sbom([_c("event-stream", eco="npm"), _c("event-stream", eco="pypi")])
    v = pol.evaluate(sbom)
    assert len(v) == 1 and v[0].kind == "banned_package" and "malicious" in v[0].detail


def test_banned_package_version_pin():
    pol = Policy(banned_packages=[{"name": "left-pad", "version": "1.0.0"}])
    assert len(pol.evaluate(_sbom([_c("left-pad", "1.0.0")]))) == 1
    assert pol.evaluate(_sbom([_c("left-pad", "1.0.1")])) == []   # other version is fine


# ── vulnerability gate ────────────────────────────────────────────────────────
def test_vuln_severity_gate():
    c = _c("django", licenses=["BSD-3-Clause"])
    c.vulnerabilities.append(Vulnerability(id="CVE-1", severity=VulnSeverity.CRITICAL, cvss=9.8))
    c.vulnerabilities.append(Vulnerability(id="CVE-2", severity=VulnSeverity.MEDIUM, cvss=5.0))
    pol = Policy(max_vuln_severity="high")        # critical > high -> violation; medium ok
    v = [x for x in pol.evaluate(_sbom([c])) if x.kind == "vulnerability"]
    assert len(v) == 1 and "CVE-1" in v[0].detail


def test_needs_audit_flag():
    assert Policy(max_vuln_severity="high").needs_audit is True
    assert Policy().needs_audit is False


# ── YAML loading ──────────────────────────────────────────────────────────────
def test_load_policy_yaml(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text(
        "licenses:\n  deny: [GPL-3.0-only]\n  unknown: deny\n"
        "banned_packages:\n  - name: request\n    ecosystem: npm\n"
        "vulnerabilities:\n  max_severity: medium\n", encoding="utf-8")
    pol = Policy.load(p)
    assert pol.license_deny == ["GPL-3.0-only"] and pol.license_unknown == "deny"
    assert pol.banned_packages[0]["name"] == "request"
    assert pol.max_vuln_severity == "medium" and pol.needs_audit
