"""Generate specs/fixtures/cases/safety_gates.json (oracle: this repo's
PatternCompiler at the stamped engine_version; regenerate on every engine
release whose safety chain changed).

Runtime-bounded design (v2):

v1 crawled: the oracle's cost_verdict on adversarial harvested patterns
burns its full deadline per call. v2 scopes work:
- harvested pool -> test_strings mode only (fast subprocess probes)
- curated per-class list -> both modes
- multiprocessing pool (8 workers), 90s wall cap per candidate via
  SIGALRM, so no single adversarial pattern can stall the run
"""

from __future__ import annotations

import json
import re
import signal
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from guard_core.detection_engine.compiler import PatternCompiler  # noqa: E402

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
    ("Pattern contains adjacent broad unbounded quantifiers", "structural_adjacent_broad"),
    ("terminator cannot be reached by", "structural_unreachable_terminator"),
    ("absorb the mandatory literal", "structural_literal_absorb"),
    ("ambiguous optional tail", "structural_ambiguous_tail"),
    ("Pattern timed out on test string", "probe_string_timeout"),
    ("probe exceeded the", "probe_subprocess_timeout"),
    ("could not construct a test string that", "unreachable_probe"),
    ("Pattern extrapolated CPU cost", "over_budget"),
    ("probe construction exceeded its deadline", "builder_deadline"),
    ("Pattern appears safe", "safe"),
]

TEST_STRINGS = ["abcdefghij", "attack-test-string-123", "x"]


def classify(reason: str) -> str:
    for prefix, cls in CLASS_RULES:
        if prefix in reason:
            return cls
    return "other"


def _worker(job: tuple[str, str]) -> tuple[str, str, bool, str, str]:
    pattern, mode = job

    def _alarm(signum: int, frame: object) -> None:
        raise TimeoutError()

    old = signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(90)
    try:
        pc = PatternCompiler()
        if mode == "test_strings":
            safe, reason = pc.validate_pattern_safety(pattern, test_strings=TEST_STRINGS)
        else:
            safe, reason = pc.validate_pattern_safety(pattern, max_content_length=10000)
        return pattern, mode, safe, reason, "ok"
    except TimeoutError:
        return pattern, mode, False, "", "timeout"
    except Exception as exc:  # noqa: BLE001
        return pattern, mode, False, f"oracle crash: {exc}", "crash"
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


def extrapolated_seconds(reason: str) -> float | None:
    m = re.search(r"cost at cap \(\d+ chars\) is ([0-9.]+)s", reason)
    return float(m.group(1)) if m else None


def main() -> None:
    jobs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for pattern, _mode in CURATED:
        if pattern not in seen:
            seen.add(pattern)
        for mode in ("test_strings", "cost_verdict"):
            jobs.append((pattern, mode))
            jobs.append((pattern, mode))
    for s in harvest():
        if s in seen:
            continue
        seen.add(s)
        jobs.append((s, "test_strings"))
        jobs.append((s, "test_strings"))
    print(f"jobs: {len(jobs)}", flush=True)

    results: dict[tuple[str, str], list[tuple[bool, str, str]]] = {}
    with ProcessPoolExecutor(max_workers=8) as pool:
        for pattern, mode, safe, reason, status in pool.map(_worker, jobs):
            results.setdefault((pattern, mode), []).append((safe, reason, status))

    cases: list[dict] = []
    per_class: dict[str, int] = {}
    drops: dict[str, int] = {}
    MAX_PER_CLASS = 8

    for (pattern, mode), runs in sorted(results.items()):
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
            drops[f"{mode}:nondeterministic"] = drops.get(f"{mode}:nondeterministic", 0) + 1
            continue
        if cls == "over_budget":
            ext = extrapolated_seconds(reason)
            if ext is None or ext < 0.5:
                drops[f"{mode}:notdecisive"] = drops.get(f"{mode}:notdecisive", 0) + 1
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

    suite = {
        "suite": "safety_gates",
        "kind": "pattern_safety",
        "spec_version": "4.1.0",
        "engine_version": "4.2.0",
        "cases": cases,
    }
    out = REPO / "specs/fixtures/cases/safety_gates.json"
    out.write_text(json.dumps(suite, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {len(cases)} cases to {out}", flush=True)
    print("per class:", json.dumps(per_class, indent=1, sort_keys=True), flush=True)
    print("drops:", json.dumps(drops, indent=1, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
