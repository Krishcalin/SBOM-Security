# CLAUDE.md — SBOM Security

## Project Overview

A software supply-chain tool that generates **CycloneDX** SBOMs from project
manifests/lockfiles, correlates components with known vulnerabilities, tracks
dependency drift between scans, and enforces license/security policy in CI. Third
of the four KIZEN tools derived from the AccuKnox "Code to Runtime" platform;
maps to AccuKnox **SBOM / supply-chain security**.

**Repository**: https://github.com/Krishcalin/SBOM-Security
**Python**: 3.10+ · **License**: MIT · **Status**: Phases 1-5 complete (49 tests)

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
│   ├── cvss.py                 # CVSS v3.x vector -> base score + severity bucket
│   ├── osv.py                  # OSV.dev client + run_audit() vuln correlation
│   ├── version.py              # cross-ecosystem version comparison
│   ├── drift.py                # diff() two component sets -> added/removed/up/downgraded
│   ├── baseline.py             # Baseline snapshot (components + known vuln ids)
│   ├── policy.py               # Policy.evaluate() -> license/package/vuln Violations
│   ├── banner.py               # ANSI-Shadow CLI banner (bare invocation)
│   └── logger.py               # structlog setup
├── parsers/
│   ├── base.py                 # BaseParser ABC (matches / parse)
│   ├── python.py               # requirements.txt, poetry.lock, Pipfile.lock
│   ├── node.py                 # package-lock.json (v1/v2/v3), yarn.lock (+ licenses)
│   ├── maven.py                # pom.xml (props/scope), gradle.lockfile
│   └── go.py                   # go.mod (require/indirect), go.sum
├── config/policy.example.yaml  # license/banned-package/severity policy template
├── docs/banner.svg             # README banner image
├── tests/test_sbom.py          # 13 pytest tests (Phase 1)
├── tests/test_phase2.py        # 10 pytest tests (Maven/Go/licenses/SPDX)
├── tests/test_phase3.py        # 10 pytest tests (CVSS/OSV/audit, no network)
├── tests/test_phase4.py        # 7 pytest tests (version/drift/baseline)
├── tests/test_phase5.py        # 9 pytest tests (policy/licenses/banned/vuln gate)
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
- **`osv.OSVClient` / `run_audit(components, client)`** — query OSV.dev by purl
  (batched), fetch each unique advisory once, parse into `Vulnerability` (CVE/OSV id,
  CVSS via `cvss.base_score`, severity bucket, fixed-in), attach to components.
  Injectable HTTP; network errors fail **safe** (`run_audit` returns False, no false
  positives). CycloneDX output gains a `vulnerabilities` array when present.
- **`cvss.base_score(vector)`** — CVSS v3.x base score; `severity_from_score()`
  buckets none/low/medium/high/critical.
- **`drift.diff(old, new)`** — group components by (ecosystem, name), compare version
  sets → `Change`s (added/removed/upgraded/downgraded via `version.compare`).
- **`Baseline`** — snapshot of components + known vuln ids; `from_sbom`, `write`,
  `load`, `as_components()` (feeds `drift.diff`), `knows_vuln(v)` (matches id/osv_id/
  aliases). Powers `drift` and `audit --baseline` (report only *new* vulns).
- **`Policy.evaluate(sbom)`** — YAML-driven license allow/deny + unknown-license
  mode, banned packages (name/ecosystem/version), and a max vulnerability severity
  gate → `Violation`s (error/warn). `needs_audit` tells the CLI to run OSV first.

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

### Phase 3 — Vulnerability correlation (COMPLETE)
- [x] `core/osv.py` — OSV.dev batch query by purl + per-id detail fetch (cached),
      fail-safe on network error; `core/cvss.py` v3.x base-score parser
- [x] `Vulnerability` model attached to components; CVE/OSV id, CVSS, severity, fixed-in
- [x] `audit` command (table/json/cyclonedx) + `--fail-on <severity>` CI gate
- [x] CycloneDX output gains a `vulnerabilities` array
- [x] 10 new pytest tests (33 total), offline (HTTP injected); live OSV verified

### Phase 4 — Dependency drift & baseline (COMPLETE)
- [x] `core/version.py` cross-ecosystem comparator; `core/drift.py` `diff()` →
      added / removed / upgraded / downgraded
- [x] `core/baseline.py` snapshot (components + known vuln ids); `drift` command
      with `--fail-on-drift`; `baseline` command (`--audit` to record known vulns)
- [x] `audit --baseline` reports only newly-introduced vulnerabilities
- [x] 7 new pytest tests (40 total); drift + baseline workflows verified live

### Phase 5 — Policy & license compliance (COMPLETE)
- [x] `core/policy.py` — `Policy.load()` (YAML) + `evaluate()` → license allow/deny,
      unknown-license mode (allow/warn/deny), banned packages, max-severity vuln gate
- [x] `config/policy.example.yaml` template
- [x] `check` command (table/json), runs OSV audit when the policy has a severity
      gate (unless `--offline`); fails the build on any error-level violation
- [x] 9 new pytest tests (49 total); license/banned/vuln gates verified live

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
python main.py audit --path .                           # OSV vuln correlation
python main.py audit --path . --fail-on high            # CI gate
python main.py audit --path . --format cyclonedx        # SBOM + vulnerabilities
python main.py baseline --path . --audit -o sbom-baseline.json   # snapshot + known vulns
python main.py drift --path . --baseline sbom-baseline.json      # added/removed/up/downgraded
python main.py audit --path . --baseline sbom-baseline.json      # only NEW vulnerabilities
python main.py check --path . --policy config/policy.example.yaml # license/package/vuln policy
python main.py list-components --path . --ecosystem npm
python main.py list-components --path . --format json
```
