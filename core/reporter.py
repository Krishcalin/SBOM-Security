"""Report generation — JSON, CSV, and a self-contained HTML supply-chain report.

Bundles the SBOM, OSV vulnerabilities, policy violations, and the GRC compliance
roll-up into one artifact. HTML is built inline (no Jinja2 dependency) and every
value is escaped. `result_to_dict()` is the canonical payload shared by the JSON
report and any tooling.
"""

from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime, timezone
from pathlib import Path

from core.compliance import framework_summary, ntia_minimum_elements
from core.models import SEVERITY_ORDER, Sbom, VulnSeverity

_SEV_COLOR = {
    "critical": "#dc3545", "high": "#fd7e14", "medium": "#ffc107",
    "low": "#0dcaf0", "none": "#6c757d", "unknown": "#6c757d",
}
_STATUS_COLOR = {"pass": "#3fb950", "partial": "#d29922", "fail": "#f85149",
                 "todo": "#8b949e", "error": "#f85149", "warn": "#d29922"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _findings(sbom: Sbom):
    return [(c, v) for c in sbom.components for v in c.vulnerabilities]


def result_to_dict(sbom: Sbom, *, violations=None, audited: bool = False) -> dict:
    findings = _findings(sbom)
    violations = violations or []
    return {
        "generated_at": _now_iso(),
        "root": sbom.root,
        "components": sbom.count,
        "by_ecosystem": sbom.by_ecosystem(),
        "vulnerable_components": sum(1 for c in sbom.components if c.vulnerabilities),
        "vulnerabilities": [{
            "component": c.name, "version": c.version, "ecosystem": c.ecosystem,
            "purl": c.purl, "id": v.id, "severity": v.severity.value, "cvss": v.cvss,
            "fixed": v.fixed,
        } for c, v in findings],
        "policy_violations": [{
            "level": x.level, "kind": x.kind, "component": x.component, "detail": x.detail,
        } for x in violations],
        "compliance": framework_summary(sbom, audited=audited,
                                        policy_evaluated=bool(violations is not None and violations != [])),
    }


def to_json(sbom: Sbom, *, violations=None, audited: bool = False) -> str:
    return json.dumps(result_to_dict(sbom, violations=violations, audited=audited), indent=2)


def to_csv(sbom: Sbom) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ecosystem", "name", "version", "purl", "direct", "scope",
                "licenses", "vulnerabilities", "max_severity"])
    for c in sbom.components:
        max_sev = ""
        if c.vulnerabilities:
            max_sev = max(c.vulnerabilities, key=lambda v: SEVERITY_ORDER.get(v.severity, 0)).severity.value
        w.writerow([c.ecosystem, c.name, c.version, c.purl,
                    "" if c.direct is None else c.direct, c.scope or "",
                    ";".join(c.licenses), len(c.vulnerabilities), max_sev])
    return buf.getvalue()


# ── HTML ──────────────────────────────────────────────────────────────────
def _badge(text: str, color: str) -> str:
    return (f'<span style="background:{color};color:#fff;padding:2px 8px;'
            f'border-radius:10px;font-size:12px;font-weight:600">{html.escape(text)}</span>')


def _cards(sbom: Sbom, findings, violations) -> str:
    errors = sum(1 for v in violations if v.level == "error")
    cards = [
        ("components", sbom.count, "#58a6ff"),
        ("vulnerable", sum(1 for c in sbom.components if c.vulnerabilities), "#fd7e14"),
        ("vulnerabilities", len(findings), "#dc3545"),
        ("policy errors", errors, "#f85149"),
    ]
    items = "".join(
        f'<div class="card"><div class="num" style="color:{col}">{n}</div><div>{lbl}</div></div>'
        for lbl, n, col in cards)
    return f'<div class="cards">{items}</div>'


def _compliance_html(sbom: Sbom, audited: bool, policy_evaluated: bool) -> str:
    rows = "".join(
        f'<tr><td>{html.escape(e.element)}</td>'
        f'<td>{_badge(e.status, _STATUS_COLOR.get(e.status, "#6c757d"))}</td>'
        f'<td class="dim">{html.escape(e.detail)}</td></tr>'
        for e in ntia_minimum_elements(sbom))
    fw = framework_summary(sbom, audited=audited, policy_evaluated=policy_evaluated)["frameworks"]
    fw_rows = ""
    for name, controls in fw.items():
        for c in controls:
            fw_rows += (f'<tr><td>{html.escape(name)}</td><td><code>{html.escape(c["id"])}</code></td>'
                        f'<td>{html.escape(c["title"])}</td>'
                        f'<td>{_badge(c["status"], _STATUS_COLOR.get(c["status"], "#6c757d"))}</td></tr>')
    return (
        '<h2>NTIA Minimum Elements</h2>'
        '<table><tr><th>Element</th><th>Status</th><th>Detail</th></tr>' + rows + '</table>'
        '<h2>Framework controls</h2>'
        '<table><tr><th>Framework</th><th>Control</th><th>Title</th><th>Status</th></tr>'
        + fw_rows + '</table>'
    )


def _vulns_html(findings) -> str:
    if not findings:
        return '<h2>Vulnerabilities</h2><p class="ok">No known vulnerabilities.</p>'
    rows = ""
    for c, v in sorted(findings, key=lambda cv: -SEVERITY_ORDER.get(cv[1].severity, 0)):
        rows += (f'<tr><td>{_badge(v.severity.value, _SEV_COLOR.get(v.severity.value, "#6c757d"))}</td>'
                 f'<td>{v.cvss if v.cvss is not None else "-"}</td>'
                 f'<td>{html.escape(c.name)} {html.escape(c.version)}</td>'
                 f'<td><code>{html.escape(v.id)}</code></td>'
                 f'<td>{html.escape(", ".join(v.fixed) or "-")}</td></tr>')
    return ('<h2>Vulnerabilities</h2><table>'
            '<tr><th>Severity</th><th>CVSS</th><th>Component</th><th>ID</th><th>Fixed in</th></tr>'
            + rows + '</table>')


def _violations_html(violations) -> str:
    if not violations:
        return ""
    rows = "".join(
        f'<tr><td>{_badge(x.level, _STATUS_COLOR.get(x.level, "#6c757d"))}</td>'
        f'<td>{html.escape(x.kind)}</td><td>{html.escape(x.component)}</td>'
        f'<td>{html.escape(x.detail)}</td></tr>' for x in violations)
    return ('<h2>Policy violations</h2><table>'
            '<tr><th>Level</th><th>Kind</th><th>Component</th><th>Detail</th></tr>'
            + rows + '</table>')


def to_html(sbom: Sbom, *, violations=None, audited: bool = False) -> str:
    violations = violations or []
    findings = _findings(sbom)
    eco = ", ".join(f"{k}: {v}" for k, v in sorted(sbom.by_ecosystem().items())) or "none"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SBOM Security Report</title>
<style>
  body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:32px;line-height:1.5}}
  h1{{margin:0 0 4px}} h2{{margin-top:32px;border-bottom:1px solid #30363d;padding-bottom:6px}}
  .meta{{color:#8b949e;font-size:14px;margin-bottom:24px}}
  .cards{{display:flex;gap:16px;flex-wrap:wrap}}
  .card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 24px;text-align:center;min-width:110px}}
  .num{{font-size:32px;font-weight:700}}
  table{{border-collapse:collapse;width:100%;margin-top:12px;font-size:14px}}
  th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #21262d;vertical-align:top}}
  th{{color:#8b949e;font-weight:600}}
  code{{background:#161b22;padding:1px 5px;border-radius:4px;color:#c9d1d9}}
  .dim{{color:#8b949e}} .ok{{color:#3fb950;font-size:18px}}
</style></head><body>
<h1>SBOM Security Report</h1>
<div class="meta">root: <code>{html.escape(sbom.root)}</code> &middot; {html.escape(eco)}
 &middot; {"audited" if audited else "not audited"} &middot; generated {_now_iso()}</div>
{_cards(sbom, findings, violations)}
{_vulns_html(findings)}
{_violations_html(violations)}
{_compliance_html(sbom, audited, bool(violations))}
</body></html>"""


def write_report(path: str | Path, sbom: Sbom, *, violations=None, audited: bool = False) -> Path:
    out = Path(path)
    ext = out.suffix.lower()
    if ext == ".json":
        text = to_json(sbom, violations=violations, audited=audited)
    elif ext == ".csv":
        text = to_csv(sbom)
    elif ext in (".html", ".htm"):
        text = to_html(sbom, violations=violations, audited=audited)
    else:
        raise ValueError(f"unsupported report extension: {ext!r} (use .json, .csv, or .html)")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    return out
