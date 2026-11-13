from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from typing import Literal, overload

from fixture_types import (
    CorpusIndex,
    DetectCase,
    EventsCase,
    JsonObject,
    JsonValue,
    MisconfigurationCase,
    PipelineCase,
    RedisCase,
    SafetyCase,
    SuiteCase,
)

from guard_core.handlers.suspatterns_handler import (
    SusPatternsManager,
    sus_patterns_handler,
)
from guard_core.models import SecurityConfig

REPO_ROOT = Path(__file__).resolve().parents[3]
CASES_DIR = REPO_ROOT / "specs" / "fixtures" / "cases"
DROP_KEYS = {"execution_time"}
FIXED_IP = "203.0.113.7"

# The fields 5.0.0 flipped or started to warn about. Every tool builds its
# SecurityConfig with these stated, so a corpus case never depends on the
# engine's own defaults of the release that runs it (D-84 item 4, LEDGER 6.60).
STAGED_FIELDS: dict[str, bool | int | str] = {
    "enable_redis": False,
    "rate_limit": 10,
    "whitelist_access_only": False,
    "redis_prefix": "guard_core:",
    "ban_on_hostile_signals": False,
    "fail_on_misconfiguration": False,
}

# The classes whose verdict comes from a clock: a loaded host may turn them into
# probe_subprocess_timeout, which no case ever pins (D-84 item 2).
TIMED_SAFETY_CLASSES = frozenset(
    {"over_budget", "probe_string_timeout", "builder_deadline", "stray_cpu_budget"}
)
LOAD_SHIFTED_SAFETY_CLASS = "probe_subprocess_timeout"


@overload
def normalize(value: JsonObject) -> JsonObject: ...


@overload
def normalize(value: JsonValue) -> JsonValue: ...


def normalize(value: JsonValue) -> JsonValue:
    if isinstance(value, dict):
        return {
            key: normalize(item) for key, item in value.items() if key not in DROP_KEYS
        }
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, float):
        return round(value, 6)
    return value


def canonical_threats(threats: list[JsonObject]) -> list[JsonObject]:
    return sorted(
        threats,
        key=lambda t: (
            str(t.get("category", "")),
            str(t.get("pattern", "")),
            t.get("position", 0) if isinstance(t.get("position"), int) else 0,
            str(t.get("type", "")),
        ),
    )


async def check_case(
    manager: SusPatternsManager, suite: str, case: DetectCase
) -> str | None:
    verdict = await manager.detect(
        case["input"]["content"], FIXED_IP, case["input"]["context"]
    )
    actual = {
        "is_threat": verdict["is_threat"],
        "threat_score": round(verdict["threat_score"], 6),
        "threats": canonical_threats([normalize(t) for t in verdict["threats"]]),
        "original_length": verdict["original_length"],
        "processed_length": verdict["processed_length"],
        "detection_method": verdict["detection_method"],
    }
    if actual != case["expected"]:
        differing = [
            key
            for key in set(actual) | set(case["expected"])
            if actual.get(key) != case["expected"].get(key)
        ]
        return f"{suite}/{case['id']}: fields {sorted(differing)} differ"
    return None


async def check_pipeline_case(suite: str, case: PipelineCase) -> str | None:
    from pipeline_harness import run_case

    observed = await run_case(case)
    expected = case["expected"]
    if len(observed) != len(expected):
        return f"{suite}/{case['id']}: drive count differs"
    for index, (actual, want) in enumerate(zip(observed, expected, strict=True)):
        # Compare only the recorded keys; the harness may observe more than
        # the corpus pins for a given drive.
        for key, want_value in want.items():
            if actual.get(key) != want_value:
                return (
                    f"{suite}/{case['id']} drive {index}: "
                    f"field {key} differs: want {want_value!r}, "
                    f"got {actual.get(key)!r}"
                )
    return None


def _matches_prefix_rule(actual: JsonObject, key: str, want_value: JsonValue) -> bool:
    from events_harness import EVENT_PREFIX_RULES

    return any(
        rule["event_type"] == actual.get("event_type")
        and rule["field"] == key
        and str(actual.get(key)).startswith(rule["prefix"])
        and str(want_value).startswith(rule["prefix"])
        for rule in EVENT_PREFIX_RULES
    )


async def check_events_case(suite: str, case: EventsCase) -> str | None:
    if case.get("xfail"):
        return None
    from events_harness import run_events_case

    observed = await run_events_case(case)
    expected = case["expected"]
    if len(observed) != len(expected):
        return (
            f"{suite}/{case['id']}: event count differs: "
            f"want {len(expected)}, got {len(observed)}"
        )
    for index, (actual, want) in enumerate(zip(observed, expected, strict=True)):
        # Compare only the pinned keys of each envelope; emitter seams
        # differ in the surface they carry.
        for key, want_value in want.items():
            if _matches_prefix_rule(actual, key, want_value):
                continue
            if normalize(actual.get(key)) != normalize(want_value):
                return (
                    f"{suite}/{case['id']} event {index}: "
                    f"field {key} differs: want {want_value!r}, "
                    f"got {actual.get(key)!r}"
                )
    return None


async def check_redis_case(suite: str, case: RedisCase) -> str | None:
    from redis_interop_cases import run_redis_case

    observed = await run_redis_case(case)
    if observed["expected"] != case["expected"]:
        for index, (actual, want) in enumerate(
            zip(observed["expected"], case["expected"], strict=False)
        ):
            if actual != want:
                return (
                    f"{suite}/{case['id']} key {index} differs: "
                    f"want {want!r}, got {actual!r}"
                )
        return f"{suite}/{case['id']}: expected key count differs"
    return None


def load_index() -> CorpusIndex:
    index: CorpusIndex = json.loads((CASES_DIR / "index.json").read_text())
    return index


@overload
def suite_cases(suite_name: Literal["safety_gates"]) -> list[SafetyCase]: ...


@overload
def suite_cases(suite_name: str) -> list[SuiteCase]: ...


def suite_cases(suite_name: str) -> list[SafetyCase] | list[SuiteCase]:
    suite = json.loads((CASES_DIR / f"{suite_name}.json").read_text())
    cases: list[SuiteCase] = suite["cases"]
    return cases


def safety_case_failure(
    case: Mapping[str, object], safe: bool, observed_class: str, reason: str = ""
) -> str | None:
    from generate_safety_gates import FAILING_CLASSES

    want = case["expected"]
    assert isinstance(want, dict)
    if observed_class in FAILING_CLASSES:
        return (
            f"safety_gates/{case['id']}: {observed_class} reason: "
            f"{reason.splitlines()[0] if reason else ''}"
        )
    if safe != want["safe"]:
        return f"safety_gates/{case['id']}: safe is {safe}, want {want['safe']}"
    accepted = {want["reason_class"]}
    if want["reason_class"] in TIMED_SAFETY_CLASSES:
        accepted.add(LOAD_SHIFTED_SAFETY_CLASS)
    if observed_class not in accepted:
        return (
            f"safety_gates/{case['id']}: reason class is {observed_class}, "
            f"want {want['reason_class']}"
        )
    return None


async def check_safety_case(suite: str, case: SafetyCase) -> str | None:
    from generate_safety_gates import classify

    from guard_core.detection_engine.compiler import PatternCompiler

    spec = case["input"]
    compiler = PatternCompiler()
    if spec["mode"] == "test_strings":
        safe, reason = compiler.validate_pattern_safety(
            spec["pattern"], test_strings=spec["test_strings"]
        )
    else:
        safe, reason = compiler.validate_pattern_safety(
            spec["pattern"], max_content_length=spec["max_content_length"]
        )
    return safety_case_failure(case, safe, classify(reason), reason)


async def replay_suites(
    names: list[str], checkers: dict[str, Callable[..., Awaitable[str | None]]]
) -> tuple[list[str], int]:
    suites = load_index()["suites"]
    failures: list[str] = []
    total = 0
    for name in names:
        kind = suites[name]["kind"]
        checker = checkers.get(kind)
        if checker is None:
            failures.append(
                f"{name}: unknown suite kind {kind!r}, none of its cases replayed"
            )
            continue
        for case in suite_cases(name):
            total += 1
            failure = await checker(name, case)
            if failure:
                failures.append(failure)
    return failures, total


async def check_misconfiguration_case(
    suite: str, case: MisconfigurationCase
) -> str | None:
    from misconfiguration_suites import (
        check_misconfiguration_case as replay_misconfiguration_case,
    )

    return await replay_misconfiguration_case(suite, case)


async def check_detect_case(suite: str, case: DetectCase) -> str | None:
    return await check_case(sus_patterns_handler, suite, case)


async def replay_corpus(*, safety: bool) -> tuple[list[str], int]:
    sus_patterns_handler.configure(SecurityConfig(**STAGED_FIELDS))
    suites = load_index()["suites"]
    checkers: dict[str, Callable[..., Awaitable[str | None]]] = {
        "detect": check_detect_case,
        "pipeline": check_pipeline_case,
        "events": check_events_case,
        "redis_interop": check_redis_case,
        "pattern_safety": check_safety_case,
        "misconfiguration": check_misconfiguration_case,
    }
    names = [
        name
        for name, meta in suites.items()
        if (meta["kind"] == "pattern_safety") == safety
    ]
    return await replay_suites(names, checkers)


async def main_async() -> int:
    safety = "--safety-only" in sys.argv[1:]
    failures, total = await replay_corpus(safety=safety)
    index = load_index()
    if failures:
        print(f"CONFORMANCE DRIFT: {len(failures)}/{total} cases differ")
        for failure in failures:
            print(f"  {failure}")
        return 1
    print(f"conformance green: {total} cases match engine {index['engine_version']}")
    return 0


def main() -> None:
    raise SystemExit(asyncio.run(main_async()))


if __name__ == "__main__":
    main()
