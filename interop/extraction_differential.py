#!/usr/bin/env python3
"""Body-extraction differential harness: py == go == php == ts == rust.

Generates a corpus of (body bytes, content-type) pairs
(extraction_corpus.py: ~70 crafted + 150 seeded random mutations), runs each
body through every family's request-body value extractor, and diffs the
(value, context, forced-category) multisets pairwise against the Python
reference surface:

  Python  the live routing of _scan_request_body rebuilt from the engine's
          own helpers (interop/py_body_surface.py, in-process)
  Go      guardcore/bodyscan.go extractBodyScanValues (unexported; probed
          with the tag-gated in-package test from interop/probes/, run
          against a disposable clone or via the docker mount)
  PHP     src/Detection/BodyFormScan.php bodyScanEntries (bin/ probe, docker
          php:8.3-cli)
  TS      the scanBodySurface routing exercised through a recording fake
          manager (packages/core vitest probe, local pnpm)
  Rust    guard_core_engine::body_scan::extract_body_scan_values (throwaway
          cargo project referencing the checkout by path)

Normalization applied before comparing (documented, detection-neutral):

  - representation: the reference decodes body bytes with surrogateescape;
    the ports decode with U+FFFD (one per byte for PHP/TS, one per maximal
    invalid run for Go/Rust). Values are canonicalized to lossy UTF-8 with
    U+FFFD runs collapsed before diffing.
  - context gates: families emit different key-context spellings (the
    reference scans JSON keys under '{context}:{key}', the Go/PHP/Rust
    walks under the plain context); contexts are normalized through the
    engine's own gate rule (context.split(':')[0] plus the trailing
    ':embedded_json' suffix) so only gate-relevant differences remain.

Comparison artifacts: per body, the multiset AND the scan order. Islands
are not compared as a separate flag: the value multiset fully captures the
binary-island reduction outcome (island corpus bodies pin it explicitly).

Run from the guard-core checkout:

    uv run python interop/extraction_differential.py

Paths default to the ecosystem sibling checkouts; override with
GUARD_EXTRACTION_GO_ROOT / GUARD_EXTRACTION_PHP_ROOT / GUARD_EXTRACTION_TS_ROOT /
GUARD_EXTRACTION_RS_ROOT. Writes a JSON report to
interop/reports/extraction_differential.json.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from extraction_corpus import corpus
from py_body_surface import surface_entries

GUARD_CORE_ROOT = Path(__file__).resolve().parent.parent
ECOSYSTEM_ROOT = GUARD_CORE_ROOT.parent.parent
INTEROP_DIR = Path(__file__).resolve().parent
REPORTS_DIR = INTEROP_DIR / "reports"
PROBES_DIR = INTEROP_DIR / "probes"

GO_ROOT = Path(
    os.environ.get(
        "GUARD_EXTRACTION_GO_ROOT", str(ECOSYSTEM_ROOT / "Golang" / "guard-core-go")
    )
)
PHP_ROOT = Path(
    os.environ.get(
        "GUARD_EXTRACTION_PHP_ROOT", str(ECOSYSTEM_ROOT / "PHP" / "guard-core-php")
    )
)
TS_ROOT = Path(
    os.environ.get(
        "GUARD_EXTRACTION_TS_ROOT",
        str(ECOSYSTEM_ROOT / "Typescript" / "guard-core-ts"),
    )
)
RS_ROOT = Path(
    os.environ.get(
        "GUARD_EXTRACTION_RS_ROOT", str(ECOSYSTEM_ROOT / "Rust" / "guard-core-rs")
    )
)

MULTIPART_FIELD_CONTEXT = "request_body:multipart_field"
EMBEDDED_SUFFIX = ":embedded_json"


def canonical_value(raw: bytes) -> str:
    """Lossy UTF-8 canonical form with U+FFFD runs collapsed."""
    text = raw.decode("utf-8", "replace")
    collapsed: list[str] = []
    previous_fffd = False
    for char in text:
        if char == "\ufffd":
            if not previous_fffd:
                collapsed.append(char)
            previous_fffd = True
        else:
            collapsed.append(char)
            previous_fffd = False
    return "".join(collapsed)


def canonical_py_value(value: str) -> str:
    return canonical_value(value.encode("utf-8", "surrogatepass"))


def gate_context(context: str) -> str:
    """The engine's own context normalization (gate-relevant part)."""
    base = context.split(":", 1)[0]
    if context.endswith(EMBEDDED_SUFFIX):
        return base + EMBEDDED_SUFFIX
    return base


def truncate_forced(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Scan lists truncated at the first forced (walk-hit) entry, inclusive.

    The reference walk returns on the first mongo-operator key; the ports
    emit the rest of the walk. Everything after the forced entry is
    first-hit noise for the detection pipeline.
    """
    truncated: list[dict[str, Any]] = []
    for entry in entries:
        truncated.append(entry)
        if entry["f"]:
            break
    return truncated


def py_surface(cases: list[tuple[str, bytes, str]]) -> dict[str, list[dict[str, Any]]]:
    surfaces: dict[str, list[dict[str, Any]]] = {}
    for label, body, content_type in cases:
        raw_body = body.decode("utf-8", "surrogateescape")
        entries = []
        for entry in surface_entries(raw_body, content_type):
            if entry.role == "name_repeat":
                # first-hit-identical multipart label re-scans (the engine's
                # per-entry loop); the ports scan the label once per part
                continue
            entries.append(
                {
                    "v": canonical_py_value(entry.value),
                    "c": gate_context(entry.context),
                    "f": entry.forced or "",
                    "role": entry.role,
                    "island": entry.island,
                }
            )
        surfaces[label] = truncate_forced(entries)
    return surfaces


def _run(
    command: list[str],
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> None:
    result = subprocess.run(
        command, capture_output=True, text=True, timeout=1800, env=env, cwd=cwd
    )
    if result.returncode != 0:
        raise SystemExit(
            f"probe failed ({' '.join(command[:6])}...): "
            f"{(result.stdout + result.stderr)[-3000:]}"
        )


def probe_input_bytes(cases: list[tuple[str, bytes, str]]) -> list[dict[str, Any]]:
    return [
        {
            "label": label,
            "body_b64": base64.b64encode(body).decode("ascii"),
            "content_type": content_type,
        }
        for label, body, content_type in cases
    ]


def _go_run(vectors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    REPORTS_DIR.mkdir(exist_ok=True)
    input_path = REPORTS_DIR / "go_extraction_input.json"
    output_path = REPORTS_DIR / "go_extraction_output.json"
    input_path.write_text(json.dumps(vectors, indent=2))
    probe_target = GO_ROOT / "guardcore" / "guardcore_body_probe_test.go"
    probe_installed = False
    if not probe_target.exists():
        shutil.copy(PROBES_DIR / "guardcore_body_probe_test.go", probe_target)
        probe_installed = True
    try:
        _run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{GO_ROOT}:/app",
                "-v",
                f"{INTEROP_DIR}:/interop",
                "-w",
                "/app",
                "-e",
                "INTEROP_EXTRACTION_INPUT=/interop/reports/go_extraction_input.json",
                "-e",
                "INTEROP_EXTRACTION_OUTPUT=/interop/reports/go_extraction_output.json",
                "-e",
                "GOCACHE=/tmp/gocache",
                "golang:1.26-alpine",
                "go",
                "test",
                "-tags",
                "interop",
                "-run",
                "^TestGuardCoreBodyProbe$",
                "-count=1",
                "./guardcore",
            ]
        )
    finally:
        if probe_installed:
            probe_target.unlink()
    loaded: list[dict[str, Any]] = json.loads(output_path.read_text())
    return loaded


def _php_run(vectors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    REPORTS_DIR.mkdir(exist_ok=True)
    input_path = REPORTS_DIR / "php_extraction_input.json"
    output_path = REPORTS_DIR / "php_extraction_output.json"
    input_path.write_text(json.dumps(vectors, indent=2))
    _run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{PHP_ROOT}:/app",
            "-v",
            f"{PROBES_DIR / 'guardcore_body_probe.php'}:"
            "/app/bin/guardcore_body_probe.php",
            "-v",
            f"{INTEROP_DIR}:/interop",
            "-w",
            "/app",
            "-e",
            "INTEROP_EXTRACTION_INPUT=/interop/reports/php_extraction_input.json",
            "-e",
            "INTEROP_EXTRACTION_OUTPUT=/interop/reports/php_extraction_output.json",
            "php:8.3-cli",
            "php",
            "bin/guardcore_body_probe.php",
        ]
    )
    loaded: list[dict[str, Any]] = json.loads(output_path.read_text())
    return loaded


def _ts_run(vectors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    REPORTS_DIR.mkdir(exist_ok=True)
    input_path = REPORTS_DIR / "ts_extraction_input.json"
    output_path = REPORTS_DIR / "ts_extraction_output.json"
    input_path.write_text(json.dumps(vectors, indent=2))
    probe_dir = TS_ROOT / "packages" / "core" / "tests" / "interop"
    probe_dir.mkdir(parents=True, exist_ok=True)
    probe_target = probe_dir / "guardcore_body_probe.test.ts"
    probe_installed = not probe_target.exists()
    if probe_installed:
        shutil.copy(PROBES_DIR / "guardcore_body_probe.test.ts", probe_target)
    env = dict(os.environ)
    env.update(
        {
            "GUARDCORE_PROBE_MODE": "extraction",
            "GUARDCORE_PROBE_INPUT": str(input_path),
            "GUARDCORE_PROBE_OUTPUT": str(output_path),
        }
    )
    try:
        _run(
            [
                str(TS_ROOT / "packages" / "core" / "node_modules" / ".bin" / "vitest"),
                "run",
                "tests/interop/guardcore_body_probe.test.ts",
                "--no-coverage",
            ],
            env=env,
            cwd=TS_ROOT / "packages" / "core",
        )
    finally:
        if probe_installed:
            probe_target.unlink()
        try:
            probe_dir.rmdir()
        except OSError:
            pass
    loaded: list[dict[str, Any]] = json.loads(output_path.read_text())
    return loaded


def _rs_materialize() -> Path:
    project = REPORTS_DIR / "rust-probe"
    project.mkdir(parents=True, exist_ok=True)
    (project / "src").mkdir(exist_ok=True)
    engine_crate = RS_ROOT / "crates" / "guard-core-engine"
    tower_crate = ECOSYSTEM_ROOT / "Rust" / "tower-guard-rs"
    (project / "Cargo.toml").write_text(
        "[package]\n"
        'name = "guardcore-rust-probe"\n'
        'version = "0.1.0"\n'
        'edition = "2021"\n\n'
        "[dependencies]\n"
        f'guard-core-engine = {{ path = "{engine_crate}" }}\n'
        f'tower-guard-rs = {{ path = "{tower_crate}" }}\n'
        'bytes = "1.10"\n'
        'http = "1.3"\n'
        'http-body-util = "0.1"\n'
        'tower = { version = "0.5", default-features = false, features = ["util"] }\n'
        'tokio = { version = "1", features = ["macros", "rt-multi-thread"] }\n'
    )
    shutil.copy(PROBES_DIR / "guardcore_rs_probe.rs", project / "src" / "main.rs")
    return project


def _rs_run(
    vectors: list[dict[str, Any]], project: Path
) -> dict[str, list[dict[str, Any]]]:
    REPORTS_DIR.mkdir(exist_ok=True)
    input_path = REPORTS_DIR / "rs_extraction_input.txt"
    output_path = REPORTS_DIR / "rs_extraction_output.txt"
    with input_path.open("w") as handle:
        for vector in vectors:
            handle.write(
                f"{vector['label']}\t{vector['content_type']}\t{vector['body_b64']}\n"
            )
    env = dict(os.environ)
    env.update(
        {
            "GUARDCORE_RS_PROBE_MODE": "extraction",
            "GUARDCORE_RS_PROBE_INPUT": str(input_path),
            "GUARDCORE_RS_PROBE_OUTPUT": str(output_path),
        }
    )
    _run(
        ["cargo", "run", "--quiet", "--manifest-path", str(project / "Cargo.toml")],
        env=env,
    )
    parsed: dict[str, list[dict[str, Any]]] = {}
    current: list[dict[str, Any]] | None = None
    for line in output_path.read_text().splitlines():
        if line.startswith("="):
            current = []
            parsed[line[1:]] = current
        elif line and current is not None:
            value_b64, context, forced = line.split("\t")
            current.append(
                {
                    "v": canonical_value(base64.b64decode(value_b64)),
                    "c": gate_context(context),
                    "f": forced,
                }
            )
    return parsed


def _entry_key(entry: dict[str, Any]) -> tuple[str, str, str]:
    return (entry["v"], entry["c"], entry["f"])


def _collapse_consecutive(
    keys: list[tuple[str, str, str]],
) -> list[tuple[str, str, str]]:
    """First-hit normalization: scanning the same value twice in a row is
    detect-identical to scanning it once.

    The reference scans the multipart field label once per ENTRY (its parts
    list is flattened to entry tuples and the label scan rides along); the
    ports scan it once per part. Collapsing consecutive duplicates on both
    sides neutralizes exactly that multiplicity difference without hiding
    any other divergence.
    """
    collapsed: list[tuple[str, str, str]] = []
    for key in keys:
        if not collapsed or collapsed[-1] != key:
            collapsed.append(key)
    return collapsed


def compare(
    label: str,
    py_entries: list[dict[str, Any]],
    family_entries: list[dict[str, Any]] | None,
    family: str,
) -> dict[str, Any]:
    if family_entries is None:
        return {"label": label, "family": family, "verdict": "MISSING"}
    py_keys = _collapse_consecutive([_entry_key(entry) for entry in py_entries])
    family_keys = _collapse_consecutive([_entry_key(entry) for entry in family_entries])
    strict_equal = Counter([_entry_key(e) for e in py_entries]) == Counter(
        [_entry_key(e) for e in family_entries]
    )
    diffs: list[str] = []
    if Counter(py_keys) != Counter(family_keys):
        missing = Counter(py_keys) - Counter(family_keys)
        extra = Counter(family_keys) - Counter(py_keys)
        for key, count in missing.items():
            diffs.append(f"py-only x{count}: {key}")
        for key, count in extra.items():
            diffs.append(f"{family}-only x{count}: {key}")
    order_equal = py_keys == family_keys
    verdict = "GREEN" if not diffs else "RED"
    return {
        "label": label,
        "family": family,
        "verdict": verdict,
        "order_equal": order_equal,
        "strict_multiset_equal": strict_equal,
        "diffs": diffs[:8],
    }


def main() -> int:
    started = time.monotonic()
    cases = corpus()
    print(f"corpus: {len(cases)} (body, content-type) pairs")

    print("python surface...")
    py_surfaces = py_surface(cases)

    vectors = probe_input_bytes(cases)

    print("go probe (docker golang:1.26-alpine)...")
    go_verdicts = _go_run(vectors)
    go_by_label: dict[str, list[dict[str, Any]]] = {}
    for entry in go_verdicts:
        go_by_label[entry["label"]] = [
            {
                "v": canonical_value(base64.b64decode(item["v"])),
                "c": gate_context(item["c"]),
                "f": item["f"],
            }
            for item in entry["entries"]
        ]

    print("php probe (docker php:8.3-cli)...")
    php_verdicts = _php_run(vectors)
    php_by_label: dict[str, list[dict[str, Any]]] = {}
    for entry in php_verdicts:
        php_by_label[entry["label"]] = [
            {
                "v": canonical_value(base64.b64decode(item["v"])),
                "c": gate_context(item["c"]),
                "f": item["f"],
            }
            for item in entry["entries"]
        ]

    print("ts probe (vitest)...")
    ts_verdicts = _ts_run(vectors)
    ts_by_label: dict[str, list[dict[str, Any]]] = {}
    for entry in ts_verdicts:
        ts_by_label[entry["label"]] = [
            {
                "v": canonical_value(base64.b64decode(item["v"])),
                "c": gate_context(item["c"]),
                "f": item["f"],
            }
            for item in entry["entries"]
        ]

    print("rust probe (cargo)...")
    project = _rs_materialize()
    rs_by_label = _rs_run(vectors, project)

    family_tables = {
        "go": go_by_label,
        "php": php_by_label,
        "ts": ts_by_label,
        "rust": rs_by_label,
    }
    for by_label in family_tables.values():
        for label, entries in by_label.items():
            by_label[label] = truncate_forced(entries)
    families = tuple(family_tables.items())

    report: dict[str, Any] = {
        "corpus_size": len(cases),
        "vectors": [],
        "by_family": {family: {"green": 0, "red": 0} for family, _ in families},
    }
    for label, _body, content_type in cases:
        entry_report: dict[str, Any] = {
            "label": label,
            "content_type": content_type,
            "py_entry_count": len(py_surfaces[label]),
            "families": [],
        }
        red = False
        for family, by_label in families:
            result = compare(label, py_surfaces[label], by_label.get(label), family)
            entry_report["families"].append(result)
            if result["verdict"] == "GREEN":
                report["by_family"][family]["green"] += 1
            else:
                report["by_family"][family]["red"] += 1
                red = True
        if red:
            print(f"RED   {label}:")
            for family_result in entry_report["families"]:
                if family_result["verdict"] != "GREEN":
                    for diff in family_result["diffs"]:
                        print(f"    [{family_result['family']}] {diff}")
        else:
            print(f"green {label}")
        report["vectors"].append(entry_report)

    report["elapsed_s"] = round(time.monotonic() - started, 2)
    REPORTS_DIR.mkdir(exist_ok=True)
    (REPORTS_DIR / "extraction_differential.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False)
    )
    total = report["corpus_size"]
    print()
    for family, counts in report["by_family"].items():
        print(f"{family}: {counts['green']}/{total} extraction multisets green")
    print(f"elapsed {report['elapsed_s']}s")
    all_green = all(counts["red"] == 0 for counts in report["by_family"].values())
    print("RESULT:", "GREEN" if all_green else "RED")
    return 0 if all_green else 1


if __name__ == "__main__":
    sys.exit(main())
