from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from guard_core.handlers.suspatterns_handler import (  # noqa: E402
    sus_patterns_handler,
)
from guard_core.models import SecurityConfig  # noqa: E402

CASES_DIR = REPO_ROOT / "specs" / "fixtures" / "cases"
DROP_KEYS = {"execution_time"}
FIXED_IP = "203.0.113.7"


def normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: normalize(item) for key, item in value.items() if key not in DROP_KEYS
        }
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, float):
        return round(value, 6)
    return value


def canonical_threats(threats: list[dict]) -> list[dict]:
    return sorted(
        threats,
        key=lambda t: (
            str(t.get("category", "")),
            str(t.get("pattern", "")),
            t.get("position", 0) if isinstance(t.get("position"), int) else 0,
            str(t.get("type", "")),
        ),
    )


async def check_case(manager: Any, suite: str, case: dict) -> str | None:
    verdict: dict = await manager.detect(
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


async def check_pipeline_case(suite: str, case: dict) -> str | None:
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


async def check_events_case(suite: str, case: dict) -> str | None:
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
            if normalize(actual.get(key)) != normalize(want_value):
                return (
                    f"{suite}/{case['id']} event {index}: "
                    f"field {key} differs: want {want_value!r}, "
                    f"got {actual.get(key)!r}"
                )
    return None


async def check_redis_case(suite: str, case: dict) -> str | None:
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


async def main_async() -> int:
    config = SecurityConfig()
    sus_patterns_handler.configure(config)
    manager = sus_patterns_handler

    index = json.loads((CASES_DIR / "index.json").read_text())
    failures: list[str] = []
    total = 0
    for suite_name, suite_meta in index["suites"].items():
        suite_path = CASES_DIR / f"{suite_name}.json"
        suite_data = json.loads(suite_path.read_text())
        kind = suite_meta.get("kind")
        if kind == "pipeline":
            checker = check_pipeline_case
        elif kind == "events":
            checker = check_events_case
        elif kind == "redis_interop":
            checker = check_redis_case
        else:
            checker = lambda suite, case: check_case(manager, suite, case)  # noqa: E731
        for case in suite_data["cases"]:
            total += 1
            failure = await checker(suite_name, case)
            if failure:
                failures.append(failure)

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
