# SBOM Security

> Generate **CycloneDX** SBOMs, correlate components with known vulnerabilities,
> and track dependency drift across Python, Node, Maven, and Go projects.

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-13%20passing-brightgreen.svg)](tests/)

Part of the KIZEN security portfolio. Where the **Secrets Scanner** finds
credentials in code, SBOM Security maps the *dependencies* that code pulls in —
the software supply chain — and the risk they carry. Maps to the AccuKnox
**SBOM / supply-chain security** capability.

**Status:** Phase 1 complete (CycloneDX generation, Python + Node) · **Python**
3.10+ · **License** MIT

---

## Why

- **CycloneDX-first.** The OWASP SBOM standard with native vulnerability/VEX
  support — the right base for a *security* SBOM (not just license inventory).
- **purl is the spine.** Every component gets a spec-correct
  [package URL](https://github.com/package-url/purl-spec) (`pkg:pypi/requests@2.31.0`),
  so vulnerability lookup, drift detection, and dedup are trivial and interoperable.
- **Lockfile-first.** Resolved, exact versions from lockfiles — an SBOM should
  record what is actually installed, not a version range.
- **Minimal dependencies.** Pure-stdlib parsing (no `toml`/`requests`); runs on
  Python 3.10+.

---

## Features (Phase 1)

- **Generate CycloneDX 1.5 SBOMs** from a project tree — `generate` (to stdout or
  a file) with metadata (timestamp, tool, root component) and per-component purl,
  licenses, and properties (ecosystem, direct/transitive, scope, source file).
- **Ecosystems:** Python (`requirements*.txt`, `poetry.lock`, `Pipfile.lock`) and
  Node (`package-lock.json` v1/v2/v3, `yarn.lock`).
- **Direct vs transitive** classification where the lockfile encodes it.
- **Smart walk** — skips `node_modules`, `.venv`, `dist`, `target`, … so the SBOM
  reflects the project's declared dependencies, not re-ingested nested manifests.
- **Dedup** by `(ecosystem, name, version)`.
- **`list-components`** — quick table or JSON inventory.

---

## Install

```bash
git clone https://github.com/Krishcalin/SBOM-Security.git
cd SBOM-Security
pip install -r requirements.txt        # or:  pip install -e ".[test]"
```

`pip install -e .` exposes a `sbom-security` console script (equivalent to
`python main.py`).

---

## Usage

```bash
# Generate a CycloneDX SBOM to stdout
python main.py generate --path .

# ...or to a file, with a custom root-component name
python main.py generate --path . -o sbom.cdx.json --app-name my-app

# Inventory the resolved components
python main.py list-components --path .
python main.py list-components --path . --ecosystem npm
python main.py list-components --path . --format json
```

### Example (CycloneDX component)

```json
{
  "type": "library",
  "name": "requests",
  "version": "2.31.0",
  "purl": "pkg:pypi/requests@2.31.0",
  "bom-ref": "pkg:pypi/requests@2.31.0",
  "properties": [
    { "name": "ecosystem", "value": "pypi" },
    { "name": "direct", "value": "true" },
    { "name": "source", "value": "requirements.txt" }
  ]
}
```

---

## How it works

```
walk project tree  →  match files to parsers  →  parse → Components  →  dedup  →  Sbom  →  CycloneDX
  skip node_modules/   python: req/poetry/pipfile   (purl auto-built)    by key       JSON
  .venv/dist/target    node:  package-lock/yarn
```

Add an ecosystem by writing a `BaseParser` subclass (declare `FILENAMES`,
implement `parse`) and registering it in `core/engine.py:default_parsers()`.

---

## Project layout

```
SBOM-Security/
├── main.py                     # Click CLI: generate, list-components
├── core/
│   ├── models.py               # Component, Sbom, ComponentType
│   ├── purl.py                 # build_purl() — package URL per ecosystem
│   ├── engine.py               # SbomGenerator — walk, dispatch, dedup
│   ├── cyclonedx.py            # CycloneDX 1.5 serializer
│   └── logger.py               # structlog setup
├── parsers/                    # BaseParser + python + node
├── rules/ (later) · config/
└── tests/test_sbom.py          # 13 pytest tests
```

See [CLAUDE.md](CLAUDE.md) for architecture detail and the full phase roadmap.

---

## Roadmap

| Phase | Scope | Status |
|------:|-------|--------|
| 1 | CycloneDX generation (Python + Node) | ✅ Complete |
| 2 | Maven + Go parsers, license/SPDX-ID normalization, SPDX export | Planned |
| 3 | Vulnerability correlation (OSV.dev), `audit`, severity gate | Planned |
| 4 | Dependency drift & baseline (added/removed/upgraded) | Planned |
| 5 | Policy & license compliance (allow/deny, banned packages) | Planned |
| 6 | HTML/JSON/CSV reports, pre-commit + CI, GRC mapping (CISA/NTIA/SCVS) | Planned |

---

## Testing

```bash
pytest                # 13 tests
pytest --cov=core --cov=parsers
```

## License

MIT
