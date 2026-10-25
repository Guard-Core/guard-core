"""Generate specs/fixtures/cases/safety_gates.json (oracle: this repo's
PatternCompiler at the stamped engine_version; regenerate on every engine
release whose safety chain changed).

Runtime-bounded design (v2):

v1 crawled: the oracle's cost_verdict on adversarial harvested patterns
burns its full deadline per call. v2 scopes work:
- harvested pool -> test_strings mode only (fast subprocess probes)
- curated per-class list -> both modes
- multiprocessing pool (8 workers), a SIGALRM wall cap per candidate
  (WORKER_WALL_CAP_SECONDS), so no single adversarial pattern can stall the run
"""

from __future__ import annotations

import json
import os
import re
import signal
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from guard_core import __version__ as engine_version
from guard_core.detection_engine.compiler import PatternCompiler

REPO = Path(__file__).resolve().parents[3]
SUITE_PATH = REPO / "specs/fixtures/cases/safety_gates.json"

HARVEST_FILES = [
    "tests/test_sus_patterns/test_redos_cost_arbiter.py",
    "tests/test_sus_patterns/test_redos_reach_probe.py",
    "tests/test_sus_patterns/test_redos_helper_branches.py",
    "tests/test_sus_patterns/test_redos_backstop_corpus.py",
    "tests/test_sus_patterns/test_custom_redos_hardening.py",
    "tests/test_sus_patterns/test_pattern_validation_latency.py",
    "tests/test_sus_patterns/test_compiler.py",
    "tests/test_sus_patterns/test_redos_unreachable_terminator.py",
]

CURATED = [
    (r"(.*)+", "both"),
    (r"(.+)+", "both"),
    (r"([a-z]+.*)+", "both"),
    (r"[invalid", "both"),
    (r"(unclosed", "both"),
    (r"*leading", "both"),
    (r"(?P<1bad>x)", "both"),
    (r"(?:\w+\s?)+$", "both"),
    (r"(a|a?)+", "both"),
    (r"(x+x+)+y", "both"),
    (r"(\d|\w)*;", "both"),
    (r"'\\s*(?:\\s+)\\s*--", "both"),
    (r"(\w+\.?)+", "both"),
    (r"<script[^>]*>", "both"),
    (r"\$\([^)]+\)", "both"),
    (r"\$\{[^}]+\}", "both"),
    (r"foo.*bar", "both"),
    (r"<!\[CDATA\[.*?\]\]>", "both"),
    (r"[a-z]+abc", "both"),
    (r"[\w-]*--", "both"),
    (r"(a|aa)+$", "cost"),
    (r"(\d+)+s", "cost"),
    (r"hello world", "cost"),
    (r"\d{3}-\d{4}", "cost"),
    (r"^\s*$", "cost"),
    (r"(?i)union\s+select", "cost"),
    (r"[a-z]+[0-9]*_?", "cost"),
    (r"\b(?:foo|bar|baz)\b", "cost"),
    (r"\d+/", "cost"),
    (r"(\w+\.?)+", "cost"),
]

CLASS_RULES: list[tuple[str, str]] = [
    ("Pattern contains dangerous construct", "dangerous_construct"),
    ("Pattern validation failed:", "compile_failed"),
    ("Pattern contains nested unbounded quantifier", "structural_nested_unbounded"),
    (
        "Pattern contains adjacent broad unbounded quantifiers",
        "structural_adjacent_broad",
    ),
    ("terminator cannot be reached by", "structural_unreachable_terminator"),
    ("absorb the mandatory literal", "structural_literal_absorb"),
    ("ambiguous optional tail", "structural_ambiguous_tail"),
    ("Pattern timed out on test string", "probe_string_timeout"),
    ("probe exceeded the", "probe_subprocess_timeout"),
    ("could not construct a test string that", "unreachable_probe"),
    ("Pattern extrapolated CPU cost", "over_budget"),
    ("exceeded its deadline", "builder_deadline"),
    ("stray verification exceeded its", "probe_subprocess_timeout"),
    ("Pattern validation probe failed", "probe_subprocess_timeout"),
    ("probe returned malformed output", "probe_subprocess_timeout"),
    ("killable-subprocess failed to run", "probe_subprocess_timeout"),
    ("killable-subprocess exited unexpectedly", "probe_subprocess_timeout"),
    ("killable-subprocess returned malformed output", "probe_subprocess_timeout"),
    ("Pattern validation cannot resolve", "unreachable_probe"),
    ("budget exceeded", "unreachable_probe"),
    ("Pattern appears safe", "safe"),
]
# Every reason the engine's pattern safety can produce has a class here, pinned by
# tests/test_safety_reason_classes.py (LEDGER 6.160). The clock and subprocess
# reasons share probe_subprocess_timeout and the construction give-ups share
# unreachable_probe: a class of its own would change the published unpinned list.

# A backstop only: the oracle bounds its own work. A pinned over_budget probe
# spends about 65 s of CPU (five samples at 32000 chars), so a 90 s wall cap
# fired on a loaded host and the case vanished (LEDGER 6.75).
WORKER_WALL_CAP_SECONDS = 600

TEST_STRINGS = ["abcdefghij", "attack-test-string-123", "x"]

# The classes decided by a clock are never selected by a run: each is a fixed
# case with its own ID, listed here, chosen once on a quiet reference run with
# margin on both sides (D-83 items 1 to 4). A listed case that no longer lands in
# its class FAILS generation (never dropped), and the ordinal path below drops
# every other result of these classes, so case selection never depends on host
# speed (LEDGER 6.75). The over_budget margin is the extrapolated cost over the
# safety budget (cap 262144 is detection_max_body_inspect_bytes); the string
# timeout margin is the observed CPU over the per-string threshold and under the
# probe's CPU kill, which bounds both sides at about 6.3x (2.0 / 0.05 = 40).
SAFETY_BUDGET_SECONDS = 0.05
PROBE_THRESHOLD_SECONDS = 0.05
PROBE_KILL_SECONDS = 2.0
STRING_TIMEOUT_MARGIN = 5.0
OVER_BUDGET_MARGIN = 100.0
STRING_TIMEOUT_PATTERN = r"\d+/"
STRING_TIMEOUT_TEST_STRING = "1" * 12000

FIXED_CASES: list[dict] = [
    {
        "id": "safety_cost_verdict_over_budget_02",
        "pattern": r"(\w|\d)*;",
        "mode": "cost_verdict",
        "max_content_length": 262144,
        "reason_class": "over_budget",
    },
    {
        "id": "safety_cost_verdict_unreachable_probe_01",
        "pattern": r"(?P<n>a)(?P=n)",
        "mode": "cost_verdict",
        "max_content_length": 10000,
        "reason_class": "unreachable_probe",
    },
    {
        "id": "safety_test_strings_probe_string_timeout_01",
        "pattern": STRING_TIMEOUT_PATTERN,
        "mode": "test_strings",
        "test_strings": [STRING_TIMEOUT_TEST_STRING],
        "reason_class": "probe_string_timeout",
    },
]
FIXED_CLASSES = {case["reason_class"] for case in FIXED_CASES}

# Classes with no fixture case, each with the reason and the unit test that pins
# it in both trees. probe_subprocess_timeout is never pinned (a loaded host turns
# every timed class into it); builder_deadline cannot sit with margin on both
# sides of a load-scaled 40 s deadline (D-91 item 1).
UNPINNED_CLASSES: dict[str, dict] = {
    "probe_subprocess_timeout": {
        "reason": "a loaded host turns every timed class into this one",
        "unit_pin": None,
    },
    "builder_deadline": {
        "reason": "no case can sit with margin on both sides of a load-scaled deadline",
        "unit_pin": (
            "tests/test_sus_patterns/test_redos_cpu_deadline.py::"
            "test_the_wall_backstop_ends_construction_that_makes_no_cpu_progress"
        ),
    },
}

# An ID names one input: when the input of a pinned case changes the old ID retires.
RETIRED_CASES: list[dict] = [
    {
        "id": "safety_cost_verdict_over_budget_01",
        "input": r"(\d|\w)*; cost_verdict cap 10000",
        "reason": (
            "extrapolated cost only 25x the budget at cap 10000; the pinned input "
            "now runs at cap 262144 (D-83 item 1: 100x or more)"
        ),
        "replaced_by": "safety_cost_verdict_over_budget_02",
    }
]


def classify(reason: str) -> str:
    for prefix, cls in CLASS_RULES:
        if prefix in reason:
            return cls
    return "other"


Job = tuple[str, str, str, str, int, list[str]]


def _normal_job(pattern: str, mode: str) -> Job:
    return (pattern, mode, pattern, mode, 10000, TEST_STRINGS)


def _fixed_job(case: dict) -> Job:
    return (
        case["id"],
        "fixed",
        case["pattern"],
        case["mode"],
        case.get("max_content_length", 10000),
        case.get("test_strings", TEST_STRINGS),
    )


def _worker(job: Job) -> tuple[str, str, bool, str, str]:
    key, key_mode, pattern, mode, cap, strings = job

    def _alarm(signum: int, frame: object) -> None:
        raise TimeoutError()

    old = signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(WORKER_WALL_CAP_SECONDS)
    try:
        pc = PatternCompiler()
        if mode == "test_strings":
            safe, reason = pc.validate_pattern_safety(pattern, test_strings=strings)
        else:
            safe, reason = pc.validate_pattern_safety(pattern, max_content_length=cap)
        return key, key_mode, safe, reason, "ok"
    except TimeoutError:
        return key, key_mode, False, "", "timeout"
    except Exception as exc:
        return key, key_mode, False, f"oracle crash: {exc}", "crash"
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def harvest() -> list[str]:
    lit = re.compile(
        r"""r'([^'\\\n]*(?:\\.[^'\\\n]*)*)'|r"([^"\\\n]*(?:\\.[^"\\\n]*)*)\""""
    )
    out: list[str] = []
    seen: set[str] = set()
    for rel in HARVEST_FILES:
        path = REPO / rel
        if not path.exists():
            continue
        for m in lit.finditer(path.read_text()):
            s = m.group(1) if m.group(1) is not None else m.group(2)
            if s in seen:
                continue
            seen.add(s)
            if 2 <= len(s) <= 120 and any(c in s for c in "()[]{}*+?|\\.^$"):
                out.append(s)
    return out


_EXTRAPOLATED = re.compile(
    r"extrapolated CPU cost at cap \((\d+) chars\) is ([0-9.]+)s"
)


def _string_timeout_cpu_seconds(case: dict) -> float:
    compiled = re.compile(case["pattern"], re.IGNORECASE | re.MULTILINE)
    start = time.process_time()
    compiled.search(case["test_strings"][0])
    return time.process_time() - start


def _fixed_reference(case: dict, reason: str) -> dict:
    cls = case["reason_class"]
    if cls == "over_budget":
        found = _EXTRAPOLATED.search(reason)
        if found is None:
            raise SystemExit(f"{case['id']}: no extrapolated cost in {reason!r}")
        extrapolated = float(found.group(2))
        margin = extrapolated / SAFETY_BUDGET_SECONDS
        if margin < OVER_BUDGET_MARGIN:
            raise SystemExit(
                f"{case['id']}: extrapolated {extrapolated}s is {margin:.1f}x the "
                f"{SAFETY_BUDGET_SECONDS}s budget, under the "
                f"{OVER_BUDGET_MARGIN}x margin"
            )
        return {
            "extrapolated_seconds": extrapolated,
            "budget_seconds": SAFETY_BUDGET_SECONDS,
            "margin": round(margin, 1),
            "load_average_at_generation": round(os.getloadavg()[0], 1),
        }
    if cls == "probe_string_timeout":
        cpu = _string_timeout_cpu_seconds(case)
        over = cpu / PROBE_THRESHOLD_SECONDS
        under = PROBE_KILL_SECONDS / cpu
        if min(over, under) < STRING_TIMEOUT_MARGIN:
            raise SystemExit(
                f"{case['id']}: observed {cpu:.3f}s CPU is {over:.1f}x over the "
                f"{PROBE_THRESHOLD_SECONDS}s threshold and {under:.1f}x under the "
                f"{PROBE_KILL_SECONDS}s kill, under the {STRING_TIMEOUT_MARGIN}x margin"
            )
        return {
            "observed_cpu_seconds": round(cpu, 3),
            "threshold_seconds": PROBE_THRESHOLD_SECONDS,
            "kill_seconds": PROBE_KILL_SECONDS,
            "margin_over_threshold": round(over, 1),
            "margin_under_kill": round(under, 1),
            "load_average_at_generation": round(os.getloadavg()[0], 1),
        }
    return {"decided_before_timing": True}


def _fixed_cases_from(results: dict) -> list[dict]:
    out: list[dict] = []
    for fixed in FIXED_CASES:
        runs = results.get((fixed["id"], "fixed"), [])
        verdicts = {
            (safe, classify(reason)) for safe, reason, status in runs if status == "ok"
        }
        if len(runs) != 2 or verdicts != {(False, fixed["reason_class"])}:
            raise SystemExit(f"fixed case {fixed['id']} left its class: {runs}")
        reason = next(reason for _safe, reason, _status in runs)
        spec: dict = {"pattern": fixed["pattern"], "mode": fixed["mode"]}
        if fixed["mode"] == "test_strings":
            spec["test_strings"] = fixed["test_strings"]
        else:
            spec["max_content_length"] = fixed["max_content_length"]
        out.append(
            {
                "id": fixed["id"],
                "input": spec,
                "expected": {"safe": False, "reason_class": fixed["reason_class"]},
                "reference": _fixed_reference(fixed, reason),
            }
        )
    return out


def build_suite() -> tuple[dict, dict[str, int], dict[str, int]]:
    jobs: list[Job] = []
    seen: set[str] = set()
    for pattern, _mode in CURATED:
        if pattern not in seen:
            seen.add(pattern)
        for mode in ("test_strings", "cost_verdict"):
            jobs.append(_normal_job(pattern, mode))
            jobs.append(_normal_job(pattern, mode))
    for s in harvest():
        if s in seen:
            continue
        seen.add(s)
        jobs.append(_normal_job(s, "test_strings"))
        jobs.append(_normal_job(s, "test_strings"))
    for fixed in FIXED_CASES:
        jobs.append(_fixed_job(fixed))
        jobs.append(_fixed_job(fixed))
    print(f"jobs: {len(jobs)}", flush=True)

    results: dict[tuple[str, str], list[tuple[bool, str, str]]] = {}
    with ProcessPoolExecutor(max_workers=8) as pool:
        for key, key_mode, safe, reason, status in pool.map(_worker, jobs):
            results.setdefault((key, key_mode), []).append((safe, reason, status))

    cases: list[dict] = []
    per_class: dict[str, int] = {}
    drops: dict[str, int] = {}
    MAX_PER_CLASS = 8

    for (pattern, mode), runs in sorted(results.items()):
        if mode == "fixed":
            continue
        ok_runs = [(s, r) for s, r, st in runs if st == "ok"]
        if len(ok_runs) < 2:
            drops[f"{mode}:allfailed"] = drops.get(f"{mode}:allfailed", 0) + 1
            continue
        verdicts = {(s, classify(r)) for s, r in ok_runs}
        if len(verdicts) != 1:
            drops[f"{mode}:unstable"] = drops.get(f"{mode}:unstable", 0) + 1
            continue
        safe, reason = ok_runs[0]
        cls = classify(reason)
        if cls == "other":
            drops[f"{mode}:other"] = drops.get(f"{mode}:other", 0) + 1
            continue
        if cls == "probe_subprocess_timeout":
            # Timing a >2s probe is host-speed dependent; pinning it would
            # make the suite flaky on faster runners. Excluded by design.
            drops[f"{mode}:nondeterministic"] = (
                drops.get(f"{mode}:nondeterministic", 0) + 1
            )
            continue
        if cls in FIXED_CLASSES:
            drops[f"{mode}:fixed_class"] = drops.get(f"{mode}:fixed_class", 0) + 1
            continue
        key = f"{mode}:{cls}"
        limit = MAX_PER_CLASS * (2 if cls == "safe" else 1)
        if per_class.get(key, 0) >= limit:
            drops[f"{key}:full"] = drops.get(f"{key}:full", 0) + 1
            continue
        per_class[key] = per_class.get(key, 0) + 1
        slug = re.sub(r"[^a-z0-9]+", "_", f"{mode}_{cls}".lower()).strip("_")
        case: dict = {
            "id": f"safety_{slug}_{per_class[key]:02d}",
            "input": {"pattern": pattern, "mode": mode},
        }
        if mode == "test_strings":
            case["input"]["test_strings"] = TEST_STRINGS
        else:
            case["input"]["max_content_length"] = 10000
        case["expected"] = {"safe": safe, "reason_class": cls}
        cases.append(case)

    for fixed_case in _fixed_cases_from(results):
        cases.append(fixed_case)
        key = f"{fixed_case['input']['mode']}:{fixed_case['expected']['reason_class']}"
        per_class[key] = 1

    suite = {
        "suite": "safety_gates",
        "kind": "pattern_safety",
        "spec_version": "4.1.0",
        "engine_version": engine_version,
        "cases": cases,
    }
    return suite, per_class, drops


def _without_reference(case: dict) -> dict:
    # The reference holds measured seconds, which differ on every run.
    return {key: value for key, value in case.items() if key != "reference"}


def check_committed() -> int:
    suite, _per_class, _drops = build_suite()
    committed = json.loads(SUITE_PATH.read_text(encoding="utf-8"))
    fresh = {c["id"]: _without_reference(c) for c in suite["cases"]}
    kept = {c["id"]: _without_reference(c) for c in committed["cases"]}
    problems = [f"only committed: {i}" for i in sorted(kept.keys() - fresh.keys())]
    problems += [f"only regenerated: {i}" for i in sorted(fresh.keys() - kept.keys())]
    problems += [
        f"differs: {i}"
        for i in sorted(kept.keys() & fresh.keys())
        if kept[i] != fresh[i]
    ]
    print(f"committed {len(kept)} cases, regenerated {len(fresh)} cases")
    print("\n".join(problems) if problems else "identical ids, inputs and expectations")
    return 1 if problems else 0


def main() -> None:
    if "--check" in sys.argv[1:]:
        raise SystemExit(check_committed())
    suite, per_class, drops = build_suite()
    cases = suite["cases"]
    out = SUITE_PATH
    out.write_text(json.dumps(suite, indent=2, ensure_ascii=False) + "\n")

    # Register the suite in the corpus index (same upsert contract as the
    # cost suite): a regen without this would silently drop the
    # safety_gates registration and the pattern-safety comparison rule.
    index_path = REPO / "specs/fixtures/cases/index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    index["suites"]["safety_gates"] = {
        "case_count": len(cases),
        "kind": "pattern_safety",
        "consumers": ["python", "go", "php", "ts", "rust", "jvm"],
        "unpinned_classes": UNPINNED_CLASSES,
        "retired_case_ids": RETIRED_CASES,
    }
    index["comparison"]["pattern_safety_records"] = (
        "compare expected.safe and expected.reason_class; the numeric parts "
        "of over-budget reason strings are host-measured and never compared; "
        "a runner whose safety chain cannot produce a reason_class yet maps "
        "the case to that class's documented divergence instead of failing "
        "silently"
    )
    index_path.write_text(json.dumps(index, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {len(cases)} cases to {out}", flush=True)
    print("per class:", json.dumps(per_class, indent=1, sort_keys=True), flush=True)
    print("drops:", json.dumps(drops, indent=1, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
