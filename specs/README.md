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

Coverage declarations per port, last audited 2026-10-10 against engine 4.3.2
with the spec 4.1.0 corpus (375 cases across 21 suites; see
fixtures/cases/index.json). `full` =
all sections implemented and conformance-green. `partial` = the section is not
yet at parity (missing stages or surfaces). `partial-with-deviations` = the
corpus is green but documented semantic divergences remain. Ports MUST keep
this honest; declaring coverage the fixtures do not verify is a conformance
violation.

| Section | py | ts | rs | go | php | jvm |
|---------|----|----|----|----|-----|-----|
| 01 contract | reference | full | full | full | full | none |
| 02 config | reference | full | full | full | full | none |
| 03 pipeline | reference | full | partial | full | full | none |
| 04 detection | reference | partial-with-deviations | partial | partial | partial-with-deviations | none |
| 05 content | reference | full | full | full | full | none |
| 06 suspatterns | reference | full | partial | full | full | none |
| 07 rate limiting | reference | full | full | full | full | none |
| 08 redis schema | reference | full | partial | partial | full | none |
| 09 ip bans | reference | full | full | full | full | none |
| 10 cloud/geo | reference | full | partial | full | full | none |
| 11 responses/headers | reference | full | full | full | full | none |
| 12 behavior/events | reference | full | partial | partial | partial | none |
| 13 documentation | reference | full | full | full | full | none |
| 14 ci/supply-chain | reference | full | partial | partial | partial | none |

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
