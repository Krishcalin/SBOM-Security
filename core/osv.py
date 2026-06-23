"""OSV.dev vulnerability correlation.

OSV (https://osv.dev) is Google's open vulnerability database, queryable by purl —
which is exactly what every Component carries. The flow:

  1. POST /v1/querybatch with all purls -> per-purl lists of advisory ids (cheap).
  2. GET /v1/vulns/{id} once per *unique* id for full details (severity, fixed).
  3. Parse each advisory into a `Vulnerability` and attach it to its component(s).

Network policy: hard timeout, batched, unique-id caching. Any network error fails
**safe** — components are left un-enriched rather than reported as vulnerable. The
HTTP layer is injectable so tests run fully offline.
"""

from __future__ import annotations

import json
import urllib.request
from urllib.error import URLError

from core.cvss import base_score, severity_from_score
from core.logger import get_logger
from core.models import Component, VulnSeverity, Vulnerability

log = get_logger("osv")

_API = "https://api.osv.dev"
_BATCH = 1000

_TEXT_SEVERITY = {
    "critical": VulnSeverity.CRITICAL, "high": VulnSeverity.HIGH,
    "moderate": VulnSeverity.MEDIUM, "medium": VulnSeverity.MEDIUM,
    "low": VulnSeverity.LOW, "none": VulnSeverity.NONE,
}


# ── HTTP (stdlib; injectable) ──────────────────────────────────────────────
def _http_post(url: str, payload: dict, timeout: float) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_get(url: str, timeout: float) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


class OSVClient:
    def __init__(self, *, timeout: float = 20.0, base: str = _API,
                 http_post=_http_post, http_get=_http_get) -> None:
        self.timeout = timeout
        self.base = base.rstrip("/")
        self._post = http_post
        self._get = http_get

    def query_batch(self, purls: list[str]) -> dict[str, list[str]]:
        """Map each purl -> list of advisory ids (one or more batched requests)."""
        mapping: dict[str, list[str]] = {}
        for start in range(0, len(purls), _BATCH):
            chunk = purls[start:start + _BATCH]
            payload = {"queries": [{"package": {"purl": p}} for p in chunk]}
            resp = self._post(f"{self.base}/v1/querybatch", payload, self.timeout)
            for purl, result in zip(chunk, resp.get("results", [])):
                ids = [v["id"] for v in (result or {}).get("vulns", []) if v.get("id")]
                if ids:
                    mapping[purl] = ids
        return mapping

    def fetch(self, vuln_id: str) -> dict:
        return self._get(f"{self.base}/v1/vulns/{vuln_id}", self.timeout)


# ── advisory parsing ───────────────────────────────────────────────────────
def _parse_severity(raw: dict) -> tuple[VulnSeverity, float | None]:
    for entry in raw.get("severity", []) or []:
        if str(entry.get("type", "")).startswith("CVSS_V3"):
            score = base_score(entry.get("score", ""))
            if score is not None:
                return VulnSeverity(severity_from_score(score)), score
    label = (raw.get("database_specific", {}) or {}).get("severity", "")
    if label:
        return _TEXT_SEVERITY.get(str(label).lower(), VulnSeverity.UNKNOWN), None
    return VulnSeverity.UNKNOWN, None


def _fixed_versions(raw: dict) -> list[str]:
    fixed: list[str] = []
    for affected in raw.get("affected", []) or []:
        for rng in affected.get("ranges", []) or []:
            for event in rng.get("events", []) or []:
                if "fixed" in event and event["fixed"] not in fixed:
                    fixed.append(event["fixed"])
    return fixed


def parse_vuln(raw: dict) -> Vulnerability:
    osv_id = raw.get("id", "")
    aliases = raw.get("aliases", []) or []
    display = next((a for a in aliases if a.startswith("CVE-")), osv_id)
    severity, cvss = _parse_severity(raw)
    summary = raw.get("summary") or (raw.get("details", "")[:140])
    return Vulnerability(
        id=display, osv_id=osv_id, aliases=aliases, summary=summary,
        severity=severity, cvss=cvss, fixed=_fixed_versions(raw),
        reference=f"https://osv.dev/vulnerability/{osv_id}" if osv_id else "",
    )


# ── orchestration ──────────────────────────────────────────────────────────
def run_audit(components: list[Component], client: OSVClient) -> bool:
    """Enrich components in place with vulnerabilities. Returns False if the OSV
    query failed entirely (offline / API error) — callers can warn rather than
    report a clean bill of health."""
    purls = sorted({c.purl for c in components if c.purl})
    if not purls:
        return True
    try:
        batch = client.query_batch(purls)
    except (URLError, OSError, ValueError) as exc:
        log.warning("osv_query_failed", error=str(exc))
        return False

    cache: dict[str, Vulnerability | None] = {}
    for comp in components:
        for vid in batch.get(comp.purl, []):
            if vid not in cache:
                try:
                    cache[vid] = parse_vuln(client.fetch(vid))
                except (URLError, OSError, ValueError) as exc:
                    log.warning("osv_fetch_failed", id=vid, error=str(exc))
                    cache[vid] = None
            vuln = cache[vid]
            if vuln is not None:
                comp.vulnerabilities.append(vuln)
    return True
