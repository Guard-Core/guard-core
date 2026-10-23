# Cross-implementation interop harness

Proves that state written by the Python reference (this repo) is honored by
the Go and PHP ports over ONE shared Redis, and vice versa. The Redis schema
(specs/08) is the wire contract; specs/07 (rate limiting) and specs/09 (IP
bans) own the semantics. Code wins over prose: every check below was
verified against `guard_core/` and the ports before being encoded here.

## Participants

| Participant | Repo | Runner | Mode |
|---|---|---|---|
| Python reference | this repo | `interop/py_participant.py` | `uv run`, real `RedisManager` / `IPBanManager` / `check_rate_limit_by_ip` / `RedisCloudIpStore` / `CloudManager` |
| Go port | `../guard-core-go` | `guardcore/interop_runner_test.go` (`//go:build interop`, in-package, env-driven) | `go test -tags interop -v -run '^TestInteropRunner$' ./guardcore` |
| PHP port | `../guard-core-php` | `bin/interop.php` | `php bin/interop.php` (env-driven phase) |

All three bind `127.0.0.1:6379` from the host and
`host.docker.internal:6379` from containers, share the single key prefix
`guard_core_interop:` on DB 0, and only ever touch keys under that prefix.
The orchestrator deletes exactly `{guard_core_interop:*}` before and after
every run, so runs are idempotent and a host Redis is left clean.

## Run

```bash
python3 interop/run.py
```

Requirements: host Redis on 6379, Docker (golang:1.26-alpine, php:8.3-cli
images), uv on PATH. Exits 0 with every check green; writes
`interop/last_run.json` and per-phase JSON reports to `interop/reports/`.

Each phase is one participant subprocess; the orchestrator asserts exit 0
and reads its JSON report (file, not stdout, so `go test` wrapper noise
does not matter). Artifacts (raw float strings, payload bytes) flow forward
so each reader phase byte-compares what the writer phase wrote.

## Phases and ledger

1. `py_write`: bans `203.0.113.7` and network `198.51.100.0/24`, seeds a
   LEGACY ban key in mapped form `{prefix}banned_ips:::ffff:203.0.113.9`,
   records 3 hits on bucket A (`{prefix}rate_limit:rate:192.0.2.10`),
   writes `cloud_ip_v2:AWS` (entries `203.0.113.0/25|us-east-1` and
   `203.0.113.128/25`) through `RedisCloudIpStore`.
2. `go_read_then_write`: migration runs inside the Go ban manager init;
   Go reads Python's bans, the migrated legacy key (value byte-exact, TTL
   preserved), the shared bucket A count (3 -> 4 through
   `RateLimitManager.CheckRateLimit`, then a blocked hit at limit 1 pins
   count 5), the AWS payload (decode + byte-exact re-encode) and the
   carve-out. Writes ban `192.0.2.66`, 2 hits on bucket B, `cloud_ip_v2:GCP`.
3. `php_read_then_write`: verifies everything from phases 1-2 (both
   writers' bans, migration state, bucket A=6 and B=3 continuity via
   blocked `checkRateLimit` hits, AWS+GCP caches + byte round-trip).
   Writes ban `192.0.2.77`, 2 hits on bucket C, `cloud_ip_v2:Azure`.
4. `py_verify`: Python honors the Go/PHP bans (raw expiry strings
   byte-equal), the migrated ban, bucket counts A=7 B=4 C=3, and all three
   cloud caches including carve-outs and byte round-trips.

Bucket ledger: A = 3(py) + 1(go obs) + 1(go crossing) + 1(php) + 1(py obs)
+ 1(py crossing) = 8; B = 2(go) + 1(php) + 1(py obs) = 4; C = 2(php) +
1(py obs) = 3. Every observation is itself a hit and is asserted against
this exact arithmetic inside the observing participant.

## Exempt-IPs phase group

Phases 5-8 prove the `exempt_ips` feature (spec 07 / guard-core #118, go
#18, php #21) behaves identically across all three families. Unlike phases
1-4 (which drive the rate-limit primitives), these phases drive each
family's REAL full pipeline with one shared config: `exempt_ips =
[192.0.2.30, 192.0.2.32]`, `blacklist = [192.0.2.32]`,
`rate_limit = 2`, over the same shared Redis and prefix.

1. `py_exempt_write`: Python builds its real check pipeline
   (`build_default_pipeline` over a minimal middleware stub carrying the
   real `SecurityConfig` and the real Redis-backed `RateLimitManager`) and
   computes the live expectations: the exempt client `192.0.2.30` takes
   limit+1 pipeline drives with only normal responses, its shared bucket
   stays EMPTY (exempt traffic never reaches the limiter), the non-exempt
   client `192.0.2.31` writes exactly 2 hits, and the blacklisted exempt IP
   `192.0.2.32` is denied 403 with no exempt flag and no bucket. Artifacts
   carry the observed counts forward.
2. `go_exempt_read_then_write`: the Go engine runs `NewEngine` over the
   same config: the exempt client passes limit+1 pipeline drives (flag set,
   nothing written), the shared non-exempt bucket is observed on an allowed
   `CheckRateLimit` hit (2 -> 3) and the pipeline drive blocks 429 at the
   crossing (pins 4), the blacklisted exempt IP is denied 403
   (`Forbidden`, no flag), and no exempt/blacklisted bucket key exists.
3. `php_exempt_read_then_write`: the PHP engine runs `GuardEngine` over
   the same config: same exempt passthrough, the shared non-exempt bucket
   is pinned on a blocked `checkRateLimit` hit (4 -> 5), the blacklisted
   exempt IP is denied 403 with no flag, and `zCard` confirms both
   exempt-owned buckets stayed empty across all three families.
4. `py_exempt_verify`: Python re-reads the shared bucket (exactly the
   php-pinned count), blocks the non-exempt client 429 at a crossing driven
   AT the pinned count (pins count+1), and re-proves the exempt passthrough
   (flag set, bucket still empty) and the blacklist-beats-exemption denial
   after every family has written.

Exempt ledger: non-exempt bucket = 2(py) + 1(go obs) + 1(go crossing) +
1(php pinned crossing) = 5 at verify, +1(py crossing) = 6 final; exempt and
blacklisted-exempt buckets = 0 at every point in every phase. Every count
assertion reads the live state or the flowed artifacts, never hardcoded
guesses.

The float-string rule (spec 08) is exercised everywhere: every ban expiry
written by any implementation is read back byte-exactly and float-parsed by
the others, and all values carry non-integer fractions (microseconds).

## Custom-pattern mixed-fleet case (guard-core 5.0.0 next to 4.4.x readers)

```bash
GUARD_CORE_LEGACY_TREE=/path/to/guard-core-v4.4.0 \
GUARD_CORE_LEGACY_PYTHON=/path/to/guard-core-v4.4.0/.venv/bin/python \
GUARD_CORE_INTEROP_REDIS_PORT=6379 \
python3 interop/run.py custom-patterns
```

Specs/08 (`patterns:custom` and `patterns:custom_list`): the Python head writes
the custom patterns to the legacy comma-joined key and to the JSON list key in
one MULTI. Every older reader still reads only the legacy key. The case proves
the ports read the head's state as a real v4.4.0 Python engine does:

1. `py_custom_patterns_write`: the head adds `zq_marker_hit`, `alpha_pattern`
   and `\bacct\d{1,3}\b` (a pattern with a comma) under four prefixes
   (`mf_v440`, `mf_go`, `mf_php`, `mf_py`) and asserts both raw values.
2. `v440_custom_patterns_read`: a real v4.4.0 checkout (its own interpreter,
   `interop/v440_participant.py`) restores `mf_v440` and reports its pattern set
   (the comma pattern arrives split into two fragments) and its verdicts.
3. `go_custom_patterns_read` and `php_custom_patterns_read`: the Go and PHP
   engines restore `mf_go` and `mf_php` and must report the same set and the
   same verdicts as step 2. Neither repo is written: Go runs
   `interop/probes/mixedfleet_custom_patterns_probe_test.go` through
   `go test -overlay` on a read-only mount, PHP runs
   `interop/probes/mixedfleet_custom_patterns_probe.php` (loading `src/`
   directly when there is no `vendor/`).
4. `py_custom_patterns_verify`: the head restores `mf_py` whole (the comma
   pattern intact) and the list key of the three old-reader prefixes is still
   what the head wrote.

`GUARD_CORE_INTEROP_REDIS_PORT` (default 6379) moves the orchestrator, the
Python participants and these probes to another Redis port. The rate-limit, ban,
cloud and exempt phases keep running the Go and PHP runners, which connect to
6379 inside their own repos, so the default run refuses a port other than 6379.

## Known contract boundaries (documented by checks, not bugs)

+ `banned_networks:*` has NO reader in any implementation, including the
+ Python reference (specs/09 discrepancy 3). Cross-impl network-ban checks
+ are wire-level via each port's own storage handler plus its own
+ canonical-network parser; the manager-level negative is asserted too.
+ Rate-limit zset members are opaque; scores are the observable floats.
+ PHP `(string)` casts quantize to 14 significant digits (noted in the PHP
+ repo's local KNOWN_GAPS.md; no parse divergence, no observable effect).
+ `cloud_ip_v2` payloads are byte-exact across all three writers since the
+ PHP port adopted Python's `", "` list separators (same category as the
+ earlier JSON_UNESCAPED_SLASHES fix).

## Rust binary-body vectors

`interop/rust_binary_vectors.py` proves rust == python 4.0.3 on
binary-decoded request bodies without Redis: the Python reference and the
guard-core-rs engine (built from branch fix/binary-noise-gate-4.0.3)
scan the same payloads in-process and their verdicts are compared. See
the script docstring for the binding build steps and the surrogateescape
mapping note. The runner exits 0 when every vector is green and writes
`interop/reports/rust_binary_vectors.json`.

## Go/PHP binary-body detect vectors

`go_php_binary_vectors.py` proves that the Go and PHP engines and the Python
reference produce identical detect verdicts on binary-decoded request bodies:
random noise, a zip upload, attacks in plain and padded forms, and
plain/accented/non-Latin text controls. Payloads mirror the honesty suite
classes from `tests/test_sus_patterns/test_pattern_binary_noise_gate.py`. A
second group pins the recon leading-separator rule from upstream PR #116
across `query_param`, `request_body`, `url_path` and the `:embedded_json`
leaf contexts; each vector carries its detect context, and probes default to
`request_body:multipart_field` when an input vector has none. A third group
pins the raw-view recon scan (upstream PR #121 and the port companions:
guard-core-go #16, guard-core-php #16, guard-core-ts #71, guard-core-rs
#21): backslash-prefixed probe values now detect in every configured
pipeline across `query_param`, `request_body`, `url_path`,
`request_body:form_field` and `request_body:multipart_field`, with the
LDAP-decoded and double-escaped controls unchanged. No Redis: the detect
stage is pure; the Go and PHP participants run inside their official docker
images against the ports' checkouts (paths default to the ecosystem
`Golang/guard-core-go` and `PHP/guard-core-php` checkouts, override with
`GUARD_CORE_GO_ROOT` / `GUARD_CORE_PHP_ROOT`).

```bash
GUARD_CORE_GO_ROOT=../guard-core-go GUARD_CORE_PHP_ROOT=../guard-core-php \
    uv run python interop/go_php_binary_vectors.py
```

## Body extraction differential (all five families)

`extraction_differential.py` proves that every family's request-body value
extractor derives the SAME scan surface from one body: the (value, context,
forced-category) multiset and scan order are diffed pairwise against the
Python reference for a corpus of 220 (body, content-type) pairs
(`extraction_corpus.py`: ~70 crafted + 150 seeded random mutations covering
form fields, multipart text/binary file parts, nested containers, JSON
walks with mongo operator keys, depth-cap boundaries, number renderings,
malformed bodies).

Participants: Python in-process (`py_body_surface.py`, rebuilt from the
engine's own helpers), Go via the tag-gated in-package probe
(`probes/guardcore_body_probe_test.go`, docker `golang:1.26-alpine`), PHP
via `probes/guardcore_body_probe.php` (docker `php:8.3-cli`), TS via
`probes/guardcore_body_probe.test.ts` (a recording fake manager driven
through the real `scanRequestWithManager` routing, local vitest), Rust via
`probes/guardcore_rs_probe.rs` (a throwaway cargo project referencing the
checkout by path). The probe files are mounted into the checkouts at run
time (or copied into disposable clones); the audited detection code is
exactly master.

Normalizations applied before comparing (documented, first-hit-neutral):
surrogateescape/U+FFFD representation mapping with U+FFFD runs collapsed,
the engine's own context-gate normalization, scan lists truncated at the
first forced (mongo-operator-key) walk hit, and the reference's per-entry
multipart label re-scans collapsed (the ports scan the label once per part;
both are first-hit-identical).

```bash
GUARD_EXTRACTION_GO_ROOT=../guard-core-go GUARD_EXTRACTION_PHP_ROOT=../guard-core-php \
    GUARD_EXTRACTION_TS_ROOT=../guard-core-ts GUARD_EXTRACTION_RS_ROOT=../guard-core-rs \
    uv run python interop/extraction_differential.py
```

### The Python model follows the engine

`py_body_surface.py` models the engine's current body surface: the embedded walk has no depth cap and skips a key or leaf it already scanned clean, its key contexts carry `[REDACTED]`, and an undeclared body is scanned only through its backslash string literals (decoded, each with its own embedded check) and then as one text. `body_surface_differential.py` keeps the model honest: it runs the engine's own `_scan_request_body` with `detect` recording every (value, context) it is asked to scan and compares that record, in order, with `surface_entries` over the 220 corpus pairs, the body inputs of the conformance fixtures and the WP19 shapes (depths 1 to 600 on every surface, escaped payloads nested one to three levels, repeated keys, flat, escaped and backslash-heavy bodies). It exits 0 only when 0 inputs differ.

```bash
uv run python interop/body_surface_differential.py
```

## Body-surface detect vectors and middleware spot checks

`body_detect_vectors.py` extends the suite with vectors that go through each
family's real body surface (extraction plus per-value detection): backslash
probes inside real bodies, bare-word innocence, island smuggling, mongo
operator keys, embedded JSON leaves, and raw-text-spanning attacks on
JSON-parsing values. Expectations are ALWAYS taken from the live Python
engine (`detect_penetration_attempt`) on the same input.

`middleware_spot_checks.py` drives ONE end-to-end blocked case (an attack
smuggled inside a binary multipart file part) and ONE innocence case
(`?system=SAP`) through each family's real middleware: Python's
`SuspiciousActivityCheck`, Go's `suspiciousActivityCheck.Check`, PHP's
`SuspiciousActivityCheck->check`, the TS `initializeSecurityMiddleware`
pipeline, and the Rust tower `GuardLayer` service.

```bash
GUARD_EXTRACTION_GO_ROOT=../guard-core-go GUARD_EXTRACTION_PHP_ROOT=../guard-core-php \
    GUARD_EXTRACTION_TS_ROOT=../guard-core-ts GUARD_EXTRACTION_RS_ROOT=../guard-core-rs \
    uv run python interop/body_detect_vectors.py
GUARD_EXTRACTION_GO_ROOT=../guard-core-go GUARD_EXTRACTION_PHP_ROOT=../guard-core-php \
    GUARD_EXTRACTION_TS_ROOT=../guard-core-ts GUARD_EXTRACTION_RS_ROOT=../guard-core-rs \
    uv run python interop/middleware_spot_checks.py
```
