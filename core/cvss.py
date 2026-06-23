"""CVSS v3.x base-score parsing.

OSV advisories carry severity as a CVSS vector string (e.g.
``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H``). This computes the v3.0/3.1
base score from that vector using the official formula, so findings can be
bucketed (none/low/medium/high/critical) and gated in CI. CVSS v4 vectors are
not parsed here (caller falls back to the advisory's textual severity).
"""

from __future__ import annotations

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}     # scope unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}      # scope changed
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    # CVSS 3.1 roundup: smallest number to one decimal place >= value
    i = round(value * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (i // 10000 + 1) / 10.0


def base_score(vector: str) -> float | None:
    """Return the CVSS v3.x base score for a vector string, or None if unparseable."""
    if not vector or "CVSS:3" not in vector:
        return None
    metrics = {}
    for part in vector.split("/"):
        if ":" in part:
            k, _, v = part.partition(":")
            metrics[k] = v
    try:
        scope_changed = metrics["S"] == "C"
        pr_table = _PR_C if scope_changed else _PR_U
        av, ac = _AV[metrics["AV"]], _AC[metrics["AC"]]
        pr, ui = pr_table[metrics["PR"]], _UI[metrics["UI"]]
        c, i, a = _CIA[metrics["C"]], _CIA[metrics["I"]], _CIA[metrics["A"]]
    except KeyError:
        return None

    isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = (1.08 if scope_changed else 1.0) * (impact + exploitability)
    return _roundup(min(raw, 10.0))


def severity_from_score(score: float | None) -> str:
    """Map a CVSS base score to the standard qualitative bucket."""
    if score is None:
        return "unknown"
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"
