"""Generate the cost_bodies corpus suite.

Large-input parity suite: verdicts are reference-generated like every other
suite (never hand-written), and index.json carries host-measured reference
timings turned into per-case wall-clock ceilings for the port runners. The
verdict half pins detect parity on inputs big enough to cross the
truncation cap; the budget half makes scan-cost parity a CI-enforced
invariant instead of an assurance.

Run: uv run python specs/fixtures/tools/generate_cost_cases.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from run_fixtures import canonical_threats, normalize  # noqa: E402

from guard_core import __version__ as engine_version  # noqa: E402
from guard_core.handlers.suspatterns_handler import (  # noqa: E402
    sus_patterns_handler,
)
from guard_core.models import SecurityConfig  # noqa: E402

CASES_DIR = REPO_ROOT / "specs" / "fixtures" / "cases"
SPEC_VERSION = "4.1.0"
FIXED_IP = "203.0.113.7"

MULTIPLIER = 30
FLOOR_MS = 300
TIMING_RUNS = 5

PROSE_UNIT = (
    "The quick brown fox jumps over the lazy dog. "
    "Books, commas, and (parentheses); numbers like 2+2=4, dates like 2026-10-05, "
    "and the words do, as, or, the appear here for no reason at all. "
)
THREAT_UNIT = "1' OR '1'='1 -- "
ENCODED_UNIT = "a%2531b%2532c%2533d%2534e%2535f"


def _noise_unit() -> str:
    """Deterministic regex-stressful filler (seeded LCG, no randomness)."""
    alphabet = "^$.*+?()[]{}|\\/%&#;:=<>~-_aeglmnorstvx0134579"
    state = 0xC0FFEE
    out = []
    for _ in range(160):
        state = (state * 6364136223846793005 + 1442695040888963407) % (1 << 64)
        out.append(alphabet[(state >> 33) % len(alphabet)])
    return "".join(out)


NOISE_UNIT = _noise_unit()


def to_size(unit: str, size: int) -> str:
    return (unit * (size // len(unit) + 1))[:size]


def build_workloads() -> list[dict]:
    prose = lambda n: to_size(PROSE_UNIT, n)  # noqa: E731
    k, m = 1024, 1024 * 1024
    workloads: list[dict] = [
        {
            "id": "cost_prose_8kib",
            "context": "request_body",
            "body": prose(8 * k),
            "note": "default prest-guard body bound; pass-path cost floor",
        },
        {
            "id": "cost_prose_64kib",
            "context": "request_body",
            "body": prose(64 * k),
            "note": "mid-size pass path",
        },
        {
            "id": "cost_prose_256kib",
            "context": "request_body",
            "body": prose(256 * k),
            "note": "at the full-scan cap; processed_length pins the boundary",
        },
        {
            "id": "cost_prose_1mib",
            "context": "request_body",
            "body": prose(m),
            "note": "over-cap: truncation must engage; cost must stay bounded",
        },
        {
            "id": "cost_encoded_64kib",
            "context": "request_body",
            "body": to_size(ENCODED_UNIT, 64 * k),
            "note": "decode pipeline work on a benign body",
        },
        {
            "id": "cost_binnoise_64kib",
            "context": "request_body",
            "body": to_size(NOISE_UNIT, 64 * k),
            "note": "binary-noise-adjacent filler: the worst per-pattern cost",
        },
        {
            "id": "cost_threat_8kib",
            "context": "request_body",
            "body": to_size(THREAT_UNIT, 8 * k),
            "note": "reject path is not cheaper than the pass path",
        },
        {
            "id": "cost_threat_tail_256kib",
            "context": "request_body",
            "body": prose(256 * k - 2048) + THREAT_UNIT * 32,
            "note": "attack inside the final 4 KiB: cap_with_tail must keep it",
        },
        {
            "id": "cost_threat_mid_1mib",
            "context": "request_body",
            "body": prose(m // 2)
            + THREAT_UNIT * 32
            + prose(m - m // 2 - 32 * len(THREAT_UNIT)),
            "note": "over-cap mid-body attack whose shape matches no attack-region "
            "indicator: the reference's indicator-driven preservation does not "
            "keep it and the verdict is benign; ports must replicate exactly",
        },
    ]
    return workloads


async def main_async() -> int:
    config = SecurityConfig()
    sus_patterns_handler.configure(config)
    manager = sus_patterns_handler

    cases: list[dict] = []
    budgets: dict[str, dict] = {}
    for wl in build_workloads():
        verdict = await manager.detect(wl["body"], FIXED_IP, wl["context"])
        expected = {
            "is_threat": verdict["is_threat"],
            "threat_score": round(verdict["threat_score"], 6),
            "threats": canonical_threats([normalize(t) for t in verdict["threats"]]),
            "original_length": verdict["original_length"],
            "processed_length": verdict["processed_length"],
            "detection_method": verdict["detection_method"],
        }
        cases.append(
            {
                "id": wl["id"],
                "input": {"content": wl["body"], "context": wl["context"]},
                "expected": expected,
                "note": wl["note"],
            }
        )
        await manager.detect(wl["body"], FIXED_IP, wl["context"])  # warmup
        samples = []
        for _ in range(TIMING_RUNS):
            t0 = time.perf_counter()
            await manager.detect(wl["body"], FIXED_IP, wl["context"])
            samples.append((time.perf_counter() - t0) * 1000.0)
        reference_ms = round(min(samples), 1)
        budgets[wl["id"]] = {
            "reference_ms": reference_ms,
            "expected_is_threat": expected["is_threat"],
        }
        print(f"{wl['id']}: threat={expected['is_threat']} ref={reference_ms}ms")

    suite = {
        "suite": "cost_bodies",
        "kind": "detect",
        "spec_version": SPEC_VERSION,
        "engine_version": engine_version,
        "cases": cases,
    }
    out = CASES_DIR / "cost_bodies.json"
    out.write_text(json.dumps(suite, indent=1) + "\n", encoding="utf-8")

    index_path = CASES_DIR / "index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    index["suites"]["cost_bodies"] = {
        "case_count": len(cases),
        "kind": "detect",
        "consumers": ["python", "go", "php", "ts", "rust"],
    }
    index["cost_budgets"] = {
        "method": (
            "ceilings are self-relative so they survive host variance: a runner "
            "measures its own best-of-3 at the 8 KiB workload (cost_prose_8kib) "
            "and every other workload must satisfy best_ms <= K * best8_ms * "
            "(size_bytes / 8192) + floor_ms, with K=5 and floor_ms=250. This "
            "catches gross superlinearity while tolerating fixed-overhead and "
            "host differences. reference_ms below is the configured reference "
            "engine's best-of-5 on the generating host, recorded for drift "
            "review only, never compared. Verdicts in this suite compare "
            "exactly like every other suite."
        ),
        "k": 5,
        "floor_ms": 250,
        "timing_runs": TIMING_RUNS,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "budgets": budgets,
    }
    index_path.write_text(json.dumps(index, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(cases)} cases) and cost_budgets into {index_path}")
    return 0


def main() -> None:
    raise SystemExit(asyncio.run(main_async()))


if __name__ == "__main__":
    main()
