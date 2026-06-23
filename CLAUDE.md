# CLAUDE.md — SBOM Security

## Project Overview

A software supply-chain tool that generates **CycloneDX** SBOMs from project
manifests/lockfiles, correlates components with known vulnerabilities, tracks
dependency drift between scans, and enforces license/security policy in CI. Third
of the four KIZEN tools derived from the AccuKnox "Code to Runtime" platform;
maps to AccuKnox **SBOM / supply-chain security**.

**Repository**: https://github.com/Krishcalin/SBOM-Security
**Python**: 3.10+ · **License**: MIT · **Status**: Phases 1-2 complete (23 tests)

---

## Architecture

```
SBOM-Security/
├── main.py                     # Click CLI: generate, list-components
├── core/
│   ├── __init__.py             # __version__
│   ├── models.py               # Component, Sbom, ComponentType
│   ├── purl.py                 # build_purl() — package URL per ecosystem
│   ├── engine.py               # SbomGenerator — walk tree, dispatch to parsers, dedup+merge
│   ├── cyclonedx.py            # CycloneDX 1.5 JSON serializer
│   ├── spdx.py                 # SPDX 2.3 JSON serializer
│   ├── licenses.py             # license string -> SPDX-ID normalization
│   └── logger.py               # structlog setup
├── parsers/
│   ├── base.py                 # BaseParser ABC (matches / parse)
│   ├── python.py               # requirements.txt, poetry.lock, Pipfile.lock
│   ├── node.py                 # package-lock.json (v1/v2/v3), yarn.lock (+ licenses)
│   ├── maven.py                # pom.xml (props/scope), gradle.lockfile
│   └── go.py                   # go.mod (require/indirect), go.sum
├── config/                     # policy / settings (later phases)
├── tests/test_sbom.py          # 13 pytest tests (Phase 1)
├── tests/test_phase2.py        # 10 pytest tests (Maven/Go/licenses/SPDX)
├── pyproject.toml
├── requirements.txt
└── README.md
```

### Core contracts

- **`BaseParser`** — `matches(path) -> bool` (by filename) + `parse(path) ->
  list[Component]`. One parser per ecosystem; lockfiles preferred over manifests
  (exact resolved versions, full transitive tree).
- **`Component`** — `name, version, ecosystem (pypi|npm|maven|golang), type, purl,
  licenses, direct, scope, source`. `purl` is auto-built in `__post_init__`.
  `key = (ecosystem, name.lower(), version)` is the dedup identity.
- **`Sbom`** — `root`, `components`, `by_ecosystem()`, `count`.
- **`SbomGenerator.generate(root)`** — walk (skipping `node_modules`/`.venv`/… so
  the SBOM is the project's *declared* deps, not re-ingested nested manifests) →
  dispatch each file to matching parsers → dedup by `key` → sorted `Sbom`.
- **`build_purl(ecosystem, name, version)`** — spec-correct purls (PEP 503 name
  normalization for pypi, scoped `%40` for npm, `group/artifact` for maven, slash-
  preserving for golang). Vulnerability correlation (Phase 3) keys on these.
- **`cyclonedx.to_cyclonedx(sbom)` / `dumps(sbom)`** — CycloneDX 1.5 JSON with
  metadata (timestamp, tool, root component) and per-component purl + properties.
- **`spdx.to_spdx(sbom)` / `dumps(sbom)`** — SPDX 2.3 JSON; each component is a
  package with a purl externalRef; DOCUMENT DESCRIBES root, root DEPENDS_ON each.
- **`licenses.normalize_spdx(raw)`** — map license spellings to SPDX IDs (unknown
  values pass through). Node parser populates `Component.licenses` from lockfiles.
- **`engine._merge(existing, new)`** — when the same component appears in multiple
  files, prefer a known `direct`/`scope`/`licenses` over an absent one (so go.mod's
  direct flags beat go.sum regardless of walk order).

### Design principles

1. **Lockfile-first** — resolved versions over manifest ranges; an SBOM records
   what is actually installed.
2. **purl is the spine** — every component gets a correct purl so downstream vuln
   lookup / drift / dedup are trivial and tool-interoperable.
3. **Don't ingest the world** — skip vendored dirs; the project's own lockfiles
   already encode the transitive tree.
4. **Data-driven & pluggable** — add an ecosystem by adding a `BaseParser`.
5. **Minimal deps** — stdlib parsing (no `toml`/`requests`); poetry.lock parsed by
   regex for 3.10 compatibility.

---

## Ecosystem coverage

| Ecosystem | Files (Phase) | purl |
|-----------|---------------|------|
| Python (pypi) | requirements*.txt, poetry.lock, Pipfile.lock (P1) | `pkg:pypi/...` |
| Node (npm) | package-lock.json v1/v2/v3, yarn.lock (P1) | `pkg:npm/...` |
| Java (maven) | pom.xml, gradle.lockfile (P2 ✓) | `pkg:maven/...` |
| Go (golang) | go.mod, go.sum (P2 ✓) | `pkg:golang/...` |

---

## Development Phases

### Phase 1 — Foundation + SBOM generation (COMPLETE)
- [x] Core models (`Component`/`Sbom`), `build_purl()`
- [x] `BaseParser` ABC + Python parser (requirements/poetry/Pipfile) + Node parser
      (package-lock v1/v2/v3, yarn.lock)
- [x] `SbomGenerator` — tree walk, vendored-dir skipping, dedup
- [x] CycloneDX 1.5 JSON serializer
- [x] CLI: `generate` (stdout/file), `list-components` (table/json)
- [x] 13 pytest tests

### Phase 2 — Ecosystem breadth + format polish (COMPLETE)
- [x] Maven parser (pom.xml with property/scope resolution, gradle.lockfile)
- [x] Go parser (go.mod require/indirect, go.sum with /go.mod de-suffixing)
- [x] License extraction (npm lockfiles) + `normalize_spdx()` SPDX-ID mapping
- [x] SPDX 2.3 JSON export (`generate --format spdx`)
- [x] Engine `_merge()` enriches dups (direct/scope/licenses win over absent)
- [x] 10 new pytest tests (23 total)

### Phase 3 — Vulnerability correlation
- [ ] OSV.dev batch API client → attach `vulnerabilities` (CVE, severity, fixed-in)
- [ ] `audit` command; CVSS severity; `--fail-on <severity>` CI gate

### Phase 4 — Dependency drift & baseline
- [ ] Diff two SBOMs: added / removed / upgraded / downgraded components
- [ ] Baseline file; alert only on new components or newly-vulnerable ones

### Phase 5 — Policy & license compliance
- [ ] License allow/deny policy (YAML), banned packages, max-severity gates
- [ ] Pinning/known-good enforcement

### Phase 6 — Reporting, hooks & GRC
- [ ] HTML/JSON/CSV reports; pre-commit hook + GitHub Actions CI
- [ ] Compliance mapping (CISA SBOM minimums, NTIA, OWASP SCVS, NIST SSDF)

---

## Coding Conventions

- Python 3.10+ (`X | Y` unions), type hints on public functions
- `structlog` only — never bare `print()` in library code (CLI uses `rich`)
- One parser per ecosystem under `parsers/`; tests mirror source under `tests/`
- Minimal dependencies — prefer stdlib parsing

---

## Running the Tool

```bash
python main.py generate --path .                       # CycloneDX to stdout
python main.py generate --path . -o sbom.cdx.json      # write to file
python main.py generate --path . --format spdx -o sbom.spdx.json
python main.py list-components --path . --ecosystem npm
python main.py list-components --path . --format json
```
