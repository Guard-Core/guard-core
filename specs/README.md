# Guard Core Behavioral Specification

Canonical, language-neutral specification of the guard-core engine's observable
behavior. One engine, six implementations: Python (reference), TypeScript, Rust,
Go, PHP, JVM (Kotlin). Every port MUST produce the same observable behavior
(verdicts, status codes, headers, Redis effects, event surfaces) while remaining
idiomatic internally.

- **Spec version**: `4.1.0` (tracks the guard-core release it was extracted from)
- **Status**: the parity matrix below is tracked as the audited baseline; the
  rest of specs/ remains local and untracked. Ports consume generated fixture
  corpora and rendered copies, not this directory directly.
- **Reference implementation**: guard-core @ `342890c1` (4.2.0)

## Ground rules

1. The Python implementation is the source of truth. Where prose and code
   disagree, code wins and the prose gets fixed.
2. Normative language is RFC 2119 style: MUST / MUST NOT / SHOULD / MAY.
3. Every normative claim carries an evidence citation (`file.py:symbol`).
4. Ports MUST NOT rename or renumber observable identifiers: check names,
   Redis key schemas, event type strings, category names, header names.
   Internal architecture is free.
5. "Full parity" is defined in [conformance.md](conformance.md). Not 1:1 with
   Python's structure (languages have quirks) but 1:1 in behavior.

## Sections

| # | File | Area |
|---|------|------|
| 01 | [01-contract.md](01-contract.md) | Porting contract: request/response/bounded-read protocols, adapter obligations |
| 02 | [02-config.md](02-config.md) | SecurityConfig: fields, defaults, validation semantics, bypass names |
| 03 | [03-pipeline.md](03-pipeline.md) | Check pipeline: order, applicability, exclusion, passive mode |
| 04 | [04-detection.md](04-detection.md) | Detection engine: compilation, safety gates, scan pools, deadlines |
| 05 | [05-content-pipeline.md](05-content-pipeline.md) | Content pipeline: decode chain, scan windows, truncation, semantic analysis |
| 06 | [06-suspatterns.md](06-suspatterns.md) | SusPatterns: categories, matching, threat scoring, autoban feed |
| 07 | [07-rate-limiting.md](07-rate-limiting.md) | Rate limiting: window semantics, tiers, fail modes |
| 08 | [08-redis-schema.md](08-redis-schema.md) | Redis key schema + serialization (cross-language interop contract) |
| 09 | [09-ip-bans.md](09-ip-bans.md) | IP bans: semantics, TTLs, migration, events |
| 10 | [10-cloud-geo.md](10-cloud-geo.md) | Cloud provider ranges, GeoIP, country filtering |
| 11 | [11-responses-headers.md](11-responses-headers.md) | Error responses, HTTPS redirect, security headers, CORS |
| 12 | [12-behavior-events.md](12-behavior-events.md) | Behavioral rules, event bus, metrics |
| 13 | [13-documentation.md](13-documentation.md) | Documentation contract: required artifacts, docs gates |
| 14 | [14-ci-supply-chain.md](14-ci-supply-chain.md) | CI, security scanning, dependency auditing, release gates |

## Parity matrix

Coverage declarations per port, last audited 2026-10-11 against engine 4.3.2
with the spec 4.1.0 corpus (375 cases across 21 suites; see
fixtures/cases/index.json). `full` =
all sections implemented and conformance-green. `partial` = the section is not
yet at parity (missing stages or surfaces). `partial-with-deviations` = the
corpus is green but documented semantic divergences remain. Ports MUST keep
this honest; declaring coverage the fixtures do not verify is a conformance
violation.

| Section | py | ts | rs | go | php | jvm |
|---------|----|----|----|----|-----|-----|
| 01 contract | reference | full | full | full | full | full |
| 02 config | reference | full | full | full | full | full |
| 03 pipeline | reference | full | partial | full | full | full |
| 04 detection | reference | partial-with-deviations | partial | partial | partial-with-deviations | full |
| 05 content | reference | full | full | full | full | full |
| 06 suspatterns | reference | full | partial | full | full | full |
| 07 rate limiting | reference | full | full | full | full | full |
| 08 redis schema | reference | full | partial | partial | full | full |
| 09 ip bans | reference | full | full | full | full | full |
| 10 cloud/geo | reference | full | partial | full | full | full |
| 11 responses/headers | reference | full | full | full | full | full |
| 12 behavior/events | reference | full | partial | partial | partial | full |
| 13 documentation | reference | full | full | full | full | full |
| 14 ci/supply-chain | reference | full | partial | partial | partial | full |

This table is a coarse baseline, not the record of deviations. The live source
of truth for what each port still owes is that engine's gap ledger:
`KNOWN_GAPS.md` in guard-core-go and guard-core-php, `conformance/README.md`
with `xfail_baseline.toml` and `pattern_ledger.toml` in guard-core-rs, and
`conformance/baseline.json` with `ts_pipeline_xfail.json` in guard-core-ts.
guard-core-jvm follows the Rust convention (`KNOWN_GAPS.md` + `conformance/`
xfail manifests + pattern ledger) from its scaffold onward. The `jvm` column
targets `full` on every section per the family's non-negotiable parity bar
(see [impl/jvm.md](impl/jvm.md) "Parity bar").
Update the ledger first, then this table.

JVM column certification (2026-10-11): sections 01-12 verified by the W5
full-corpus gate (375 cases + 9 cost budgets, 0 failing, 8 ledgered entries:
2 events reason-string shapes at the TS floor, 6 pattern-safety timing facts
at the RS class) and the every-feature matrix in guard-core-jvm
`docs/every-feature-matrix.md` (880 rows: 826 FULL, 54 IDIOMATIC, 0 PARTIAL,
0 MISSING). Sections 13 and 14 closed in W8d (2026-10-11): governance artifacts
(`SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`) in all four family
repos; the docs tree with a strict docs build in CI (engine: full taxonomy
including the generated 129-field configuration reference and the Dokka API
jars; adapters and agent: index/installation/api/examples sets, mirroring the
Rust family shape); dependency auditing (osv-scanner v2.6.0, checksum-pinned,
over the committed gradle.lockfile state, with per-advisory reasoned
suppressions and documented removal triggers); weekly scheduled scanning
(the code-ql cron plus a scheduled-lint workflow mirroring the Go
convention); Dependabot for gradle + github-actions in all four repos; and
committed lockfiles (gradle dependency locking, enforced on every
resolution). Release engineering landed in W8b. Evidence:
guard-core-jvm#19, spring-boot-guard#5, ktor-guard#4, guard-agent-jvm#4.

## Per-language implementation specs

[impl/](impl/), thin, language-specific work orders. The behavioral spec owns
what ports must do; these own how each language does it: API surface sketches,
regex-engine decisions (Go/Rust RE2-family translation ledgers vs PHP PCRE
backtracking), runtime-model consequences (PHP shared-nothing), edge/worker
splits (TS), and crate layout (Rust).

- [impl/go.md](impl/go.md)
- [impl/php.md](impl/php.md)
- [impl/ts-catchup.md](impl/ts-catchup.md)
- [impl/rs.md](impl/rs.md)
- [impl/jvm.md](impl/jvm.md)

## Fixture corpus

[fixtures/](fixtures/README.md), executable conformance data. JSON corpora of
inputs and expected verdicts, generated from the reference implementation.
Every port's CI runs the same corpus; a red corpus means the port has drifted
or guard-core behavior changed without a spec bump.
