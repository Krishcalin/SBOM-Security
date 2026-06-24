"""GRC / compliance mapping for SBOM standards.

Turns a scan into audit evidence against the frameworks that govern software
supply-chain transparency:

  - **NTIA Minimum Elements** (2021) — the baseline an SBOM must carry.
  - **CISA SBOM** — builds on the NTIA minimum elements.
  - **OWASP SCVS** — Software Component Verification Standard controls.
  - **NIST SSDF (SP 800-218)** — secure-development practices for components.

`ntia_minimum_elements()` scores how well the generated SBOM satisfies each NTIA
element; `framework_summary()` maps the tool's capabilities (inventory, standard
format, vuln correlation, license capture) to named controls with a live status.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from core.models import Sbom


@dataclass
class ElementStatus:
    element: str
    status: str    # pass | partial | fail
    detail: str


def _coverage_status(n: int, total: int) -> str:
    if total and n == total:
        return "pass"
    return "partial" if n else "fail"


def ntia_minimum_elements(sbom: Sbom) -> list[ElementStatus]:
    comps = sbom.components
    total = len(comps)
    with_version = sum(1 for c in comps if c.version)
    with_purl = sum(1 for c in comps if c.purl)
    with_rel = sum(1 for c in comps if c.direct is not None)
    with_lic = sum(1 for c in comps if c.licenses)
    return [
        ElementStatus("Author of SBOM data", "pass", "tool: sbom-security"),
        ElementStatus("Timestamp", "pass", "recorded in SBOM metadata"),
        ElementStatus("Component name", "pass" if total else "fail", f"{total} components"),
        ElementStatus("Component version", _coverage_status(with_version, total),
                      f"{with_version}/{total} with version"),
        ElementStatus("Unique identifiers (purl)", _coverage_status(with_purl, total),
                      f"{with_purl}/{total} with purl"),
        ElementStatus("Dependency relationship", _coverage_status(with_rel, total),
                      f"{with_rel}/{total} direct/transitive known"),
        ElementStatus("Supplier name", "partial", "not derivable from lockfiles"),
        ElementStatus("License (extended element)", _coverage_status(with_lic, total),
                      f"{with_lic}/{total} with license"),
    ]


def _license_coverage(sbom: Sbom) -> int:
    total = len(sbom.components)
    if not total:
        return 0
    return round(100 * sum(1 for c in sbom.components if c.licenses) / total)


def framework_summary(sbom: Sbom, *, audited: bool, policy_evaluated: bool) -> dict:
    vuln_status = "pass" if audited else "todo"
    lic_cov = _license_coverage(sbom)
    lic_status = "pass" if lic_cov == 100 else ("partial" if lic_cov else "fail")
    ntia = ntia_minimum_elements(sbom)
    ntia_overall = "pass" if all(e.status == "pass" for e in ntia[:6]) else "partial"

    frameworks = {
        "CISA SBOM": [
            {"id": "Minimum Elements", "title": "NTIA minimum elements present",
             "status": ntia_overall},
        ],
        "OWASP SCVS": [
            {"id": "V1.1", "title": "Complete inventory of components", "status": "pass"},
            {"id": "V2.4", "title": "SBOM in a standard format (CycloneDX/SPDX)", "status": "pass"},
            {"id": "V5.10", "title": "Components checked for known vulnerabilities",
             "status": vuln_status},
            {"id": "V6.1", "title": "License of each component identified", "status": lic_status},
            {"id": "V1.7", "title": "Policy enforced on components",
             "status": "pass" if policy_evaluated else "todo"},
        ],
        "NIST SSDF (800-218)": [
            {"id": "PS.3.2", "title": "Maintain provenance / SBOM for software", "status": "pass"},
            {"id": "PW.4.1", "title": "Track and review third-party components", "status": "pass"},
            {"id": "RV.1.1", "title": "Identify vulnerabilities in components",
             "status": vuln_status},
        ],
    }
    return {
        "ntia_minimum_elements": [asdict(e) for e in ntia],
        "frameworks": frameworks,
        "license_coverage_pct": lic_cov,
        "audited": audited,
    }
