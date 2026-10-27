#!/usr/bin/env python3
"""Rust == Python 4.0.3 binary-body detect vectors.

Proves that the guard-core-rs engine (fix/binary-noise-gate-4.0.3) and the
Python reference (guard-core 4.0.3, the binary-body noise gate from commit
436d6f72) produce identical detect verdicts on binary-decoded request
bodies: random noise, a zip upload, attacks buried in binary padding, and
plain/accented/non-Latin text controls.

The payloads are the same classes (and, for the noise seeds, the same
bytes) as guard-core's tests/test_sus_patterns/
test_pattern_binary_noise_gate.py honesty suite.

Run
---

1. Build the Rust detect binding from the guard-core-rs checkout
   (branch fix/binary-noise-gate-4.0.3):

       RUSTFLAGS="-C link-arg=-undefined -C link-arg=dynamic_lookup" \
           cargo build -p guard-core-python
       cp target/debug/libguard_core_rs.dylib <somewhere on sys.path>/guard_core_rs.so

   (on Linux: cp target/debug/libguard_core_rs.so <sys.path>/guard_core_rs.so)

2. Point the script at the module and run it from the guard-core checkout:

       GUARD_CORE_RS_SO=/path/to/guard_core_rs.so \
           uv run python interop/rust_binary_vectors.py

Exits 0 with every vector green; writes a JSON report to
interop/reports/rust_binary_vectors.json. Requires no Redis: the detect
stage is pure and both participants scan in-process.
"""

from __future__ import annotations

import asyncio
import importlib.util
import io
import json
import os
import random
import sys
import time
import zipfile
from pathlib import Path
from typing import Any

from guard_core.handlers.suspatterns_handler import DetectionResult

GUARD_CORE_RS_SO = os.environ.get("GUARD_CORE_RS_SO")
_MULTIPART_FIELD_CONTEXT = "request_body:multipart_field"
_NOISE_SIZE = 262144
# Same seeds and decode views as the upstream honesty suite; the Rust test
# reproduces these byte streams with an in-test MT19937 reimplementation.
_NOISE_SEEDS = (1, 3)
_DECODED_VIEWS = ("latin-1", "utf-8-surrogateescape")

_ATTACK_PAYLOADS = (
    "`rm -rf /`",
    "$(cat /etc/passwd)",
    "c'a't config.ini",
    "'; DROP TABLE users;--",
    "../../../etc/passwd",
)

_PLAIN_TEXT_SAMPLES = (
    "Café résumé naïve décor sélection",
    "日本語のテキストです。中国語與繁體字。한국어 텍스트",
    "кириллица и русский текст",
)

_BURIED_FRAGMENTS = (
    "\x85" * 200 + ".." + "\x9f\x9e\x9d\x9c" + "/" + "\x87" * 200,
    "\x85" * 200 + "$(cat /etc/passwd)" + "\x87" * 200,
)

_CONTROL_ONLY = (
    "\x00" * 500,
    "".join(chr(i) for i in range(1, 32)) * 40,
    "\x7f" * 300,
)


def _noise_bytes(seed: int) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.randrange(256) for _ in range(_NOISE_SIZE))


def _decoded_noise(seed: int, decoding: str) -> str:
    raw = _noise_bytes(seed)
    if decoding == "latin-1":
        return raw.decode("latin-1")
    return raw.decode("utf-8", errors="surrogateescape")


def _zip_bytes(seed: int) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("attachment.bin", _noise_bytes(seed)[:50000])
    return buffer.getvalue()


def _vectors() -> list[tuple[str, str, bool]]:
    """(label, payload, should_be_threat_in_python) triples."""
    vectors: list[tuple[str, str, bool]] = []
    for seed in _NOISE_SEEDS:
        for decoding in _DECODED_VIEWS:
            vectors.append(
                (f"noise_{seed}_{decoding}", _decoded_noise(seed, decoding), False)
            )
    vectors.append(
        (
            "zip_upload",
            _zip_bytes(seed=11).decode("utf-8", errors="surrogateescape"),
            False,
        )
    )
    for i, payload in enumerate(_ATTACK_PAYLOADS):
        vectors.append((f"attack_{i}", payload, True))
    for i, sample in enumerate(_PLAIN_TEXT_SAMPLES):
        vectors.append((f"text_{i}", sample, False))
        vectors.append((f"text_backtick_{i}", f"{sample}; `rm -rf /`", True))
    vectors.append(("near_start", "../../../etc/passwd and more prose here", True))
    vectors.append(("near_end", "prose " * 30 + "../../../etc/passwd", True))
    vectors.append(("short_margin", "café '; DELETE FROM users;--", True))
    for i, control_only in enumerate(_CONTROL_ONLY):
        vectors.append((f"control_only_{i}", control_only, False))
    for i, payload in enumerate(_BURIED_FRAGMENTS):
        vectors.append((f"buried_{i}", payload, False))
    return vectors


def _rust_payload(payload: str) -> tuple[str, bool]:
    """Map a Python surrogateescape string into the Rust engine's str world.

    The reference decodes request bytes with surrogateescape, so undecodable
    bytes surface as U+DC80..U+DCFF surrogates. The Rust engine scans valid
    UTF-8 and represents undecodable bytes as U+FFFD (an artifact class in
    both engines). Re-encode to the original bytes and lossily decode so the
    Rust participant receives the engine's own representation.
    """
    try:
        payload.encode("utf-8")
        return payload, True
    except UnicodeEncodeError:
        return payload.encode("utf-8", "surrogateescape").decode(
            "utf-8", "replace"
        ), False


def _load_rust_binding() -> Any:
    if not GUARD_CORE_RS_SO:
        print(
            "GUARD_CORE_RS_SO not set; build the guard-core-rs detect binding",
            file=sys.stderr,
        )
        return None
    spec = importlib.util.spec_from_file_location("guard_core_rs", GUARD_CORE_RS_SO)
    if spec is None or spec.loader is None:
        print(f"cannot load module spec from {GUARD_CORE_RS_SO}", file=sys.stderr)
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _compare(
    py_verdict: DetectionResult, rust_verdict: dict, payload_is_unmapped: bool
) -> list[str]:
    diffs: list[str] = []
    if bool(py_verdict["is_threat"]) != bool(rust_verdict["is_threat"]):
        diffs.append(
            f"is_threat {py_verdict['is_threat']} != {rust_verdict['is_threat']}"
        )
    py_score = round(py_verdict["threat_score"], 6)
    rust_score = round(rust_verdict["threat_score"], 6)
    if py_score != rust_score:
        diffs.append(f"threat_score {py_score:.6f} != {rust_score:.6f}")
    # original_length is only comparable when the payload crossed the
    # boundary unchanged; surrogate-mapped payloads legitimately shift the
    # code-point count (per-byte surrogates vs collapsed U+FFFD runs)
    if (
        payload_is_unmapped
        and py_verdict["original_length"] != rust_verdict["original_length"]
    ):
        diffs.append("original_length")
    py_threats = sorted(
        (t["pattern"], t.get("category", "")) for t in py_verdict["threats"]
    )
    rust_threats = sorted(
        (
            t.get("pattern", t.get("attack_type", "")),
            t.get("category", t.get("type", "")),
        )
        for t in rust_verdict["threats"]
    )
    if py_threats != rust_threats:
        diffs.append(f"threats {py_threats} != {rust_threats}")
    return diffs


def main() -> int:
    from guard_core.handlers.suspatterns_handler import SusPatternsManager
    from guard_core.models import SecurityConfig

    rust = _load_rust_binding()
    if rust is None:
        return 2

    config = SecurityConfig(
        detection_compiler_timeout=2.0,
        detection_max_content_length=10000,
        detection_preserve_attack_patterns=True,
        detection_semantic_threshold=0.7,
        detection_anomaly_threshold=3.0,
        detection_slow_pattern_threshold=0.1,
        detection_monitor_history_size=1000,
        detection_max_tracked_patterns=1000,
    )
    manager = SusPatternsManager(config)

    report: dict[str, Any] = {"vectors": [], "green": 0, "red": 0}
    started = time.monotonic()

    async def _detect(payload: str) -> DetectionResult:
        return await manager.detect(
            payload, "127.0.0.1", context=_MULTIPART_FIELD_CONTEXT
        )

    for label, payload, _expected in _vectors():
        py_verdict = asyncio.run(_detect(payload))
        rust_payload, payload_is_unmapped = _rust_payload(payload)
        rust_verdict = rust.detect_verdict(rust_payload, _MULTIPART_FIELD_CONTEXT)
        diffs = _compare(py_verdict, rust_verdict, payload_is_unmapped)
        entry = {
            "label": label,
            "length": len(payload),
            "py_is_threat": bool(py_verdict["is_threat"]),
            "rust_is_threat": bool(rust_verdict["is_threat"]),
            "diffs": diffs,
        }
        report["vectors"].append(entry)
        if diffs:
            report["red"] += 1
            print(f"RED   {label}: {diffs}")
        else:
            report["green"] += 1
            print(f"green {label} (is_threat={entry['py_is_threat']})")

    report["elapsed_s"] = round(time.monotonic() - started, 2)
    reports = Path(__file__).parent / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "rust_binary_vectors.json").write_text(json.dumps(report, indent=2))
    total = report["green"] + report["red"]
    print(f"\ntotal: {report['green']}/{total} vectors green in {report['elapsed_s']}s")
    print("RESULT:", "GREEN" if report["red"] == 0 else "RED")
    return 0 if report["red"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
