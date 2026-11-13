"""Builds the misconfiguration suites of the corpus from the curated inputs.

``generate_fixtures.py`` calls ``run_misconfiguration_suites``; ``run_fixtures.py``
calls ``check_misconfiguration_case`` for the replay.
"""

from __future__ import annotations

from typing import cast

from fixture_types import JsonObject, MisconfigurationCase
from misconfiguration_cases import MISCONFIGURATION_SUITES, MisconfigurationCaseInput
from misconfiguration_harness import (
    SUITE_FILES,
    intended_kinds,
    run_misconfiguration_case,
)

from guard_core._misconfiguration_kinds import HOST_DEPENDENT_KINDS, KINDS

MISCONFIGURATION_CONSUMERS = ["python"]

COMPARISON = (
    "compare expected.raises exactly, and expected.reported and expected.fatal as "
    "sorted multisets of [kind, subject] pairs; the English message is never "
    "compared and no case encodes which problem came first. reported is every "
    "problem a run with fail_on_misconfiguration=False records, fatal is every "
    "error-severity problem the one raise of a run with "
    "fail_on_misconfiguration=True carries, so a warn kind is never fatal. "
    "With the flag true the engine still logs every warn problem and logs no error "
    "problem, so the log of that run equals the warn-severity part of reported. "
    "A kind "
    "marked fatal_only in the suite kinds block is checked only while the flag is "
    "true and so appears in fatal and never in reported. A runner that does not "
    "implement a kind lists it as deferred; a runner meeting a suite kind it does "
    "not list as deferred fails closed"
)

_SHARED_DOC = (
    "Misconfiguration suite. Each case drives the reference engine twice on the "
    "same input: once with fail_on_misconfiguration=False (expected.reported) and "
    "once with fail_on_misconfiguration=True (expected.raises, expected.fatal). "
    "A pair is [kind, subject]; subject is null when the kind has none. The kinds "
    "block lists every kind the file can hold with its severity (error or warn), "
    "scope, what the subject is and what the kind means. Only kind and subject "
    "are normative."
)
SUITE_DOCS = {
    "misconfiguration_config": (
        f"{_SHARED_DOC} Input: config, the stated SecurityConfig fields "
        "(snake_case, JSON safe, a tuple is a [limit, window] array); the runner "
        "adds fail_on_misconfiguration itself unless flag_stated is false, which "
        "leaves it unset. A config states exactly what it lists, because the "
        "changed_default.* kinds report a field the config leaves unset."
    ),
    "misconfiguration_dynamic_rules": (
        f"{_SHARED_DOC} Input: dynamic_rules, the DynamicRulesProtocol fields the "
        "validator reads; a field the case leaves out is empty or null. Every "
        "problem rejects the whole rule set, so fatal repeats reported and the "
        "flag changes nothing."
    ),
    "misconfiguration_decorators": (
        f"{_SHARED_DOC} Input: config as in misconfiguration_config, geo (null or "
        '"stub", a configured GeoIP handler) and decorators, a list of {name, args} '
        "applied one by one to a fresh function with the Python keyword names. "
        "reported is the union over the decorators and fatal the union of what each "
        "decorator's raise carries."
    ),
    "misconfiguration_runtime": (
        f"{_SHARED_DOC} Tier 2: each case names a seam (ban_thresholds, nat64, "
        "redis_handler, country_decorators, ipv6_prefix_length, endpoint_key_routes, "
        "exclude_paths_routes, declared_path_params, lazy_init_without_redis, "
        "ipinfo_download_url_ignored, purge_on_start_left_set) and gives that "
        "seam's stubs; a port wires the same stubs around its own reporter. The "
        "reference "
        "reports a default redis_prefix once per process; a runner resets that "
        "memory per case."
    ),
}


def _kinds_block(suite: str, observed: set[str]) -> JsonObject:
    scope = SUITE_FILES[suite]
    return {
        kind: {
            "severity": info.severity,
            "scope": info.scope,
            "subject": info.subject,
            "description": info.description,
            **({"fatal_only": True} if info.fatal_only else {}),
            **({"host_dependent": True} if kind in HOST_DEPENDENT_KINDS else {}),
        }
        for kind, info in sorted(KINDS.items())
        if info.scope == scope or kind in observed
    }


async def _observe_case(suite: str, case: MisconfigurationCaseInput) -> JsonObject:
    expected = await run_misconfiguration_case(suite, case["input"])
    observed = intended_kinds(expected)
    if observed != sorted(case["intends"]):
        raise SystemExit(
            f"{suite}/{case['id']}: the case intends {sorted(case['intends'])} but "
            f"the engine reports {observed}: fix the case or the engine, never "
            "freeze this as the expectation"
        )
    return {"id": case["id"], "input": case["input"], "expected": expected}


def _coverage_gaps(entries_by_suite: dict[str, list[JsonObject]]) -> list[str]:
    single_positive: set[str] = set()
    for entries in entries_by_suite.values():
        for entry in entries:
            expected = cast("JsonObject", entry["expected"])
            kinds = intended_kinds(expected)
            if len(kinds) == 1:
                single_positive.add(kinds[0])
    wanted = set(KINDS) - HOST_DEPENDENT_KINDS
    return sorted(wanted - single_positive)


async def run_misconfiguration_suites(
    spec_version: str, engine_version: str
) -> dict[str, dict]:
    entries_by_suite: dict[str, list[JsonObject]] = {}
    for suite, build in MISCONFIGURATION_SUITES.items():
        cases = build()
        ids = [case["id"] for case in cases]
        if len(ids) != len(set(ids)):
            raise SystemExit(f"{suite}: duplicate case ids")
        entries_by_suite[suite] = [await _observe_case(suite, case) for case in cases]
    gaps = _coverage_gaps(entries_by_suite)
    if gaps:
        raise SystemExit(
            f"kinds with no single-kind positive case in any suite: {gaps}"
        )
    results: dict[str, dict] = {}
    for suite, entries in entries_by_suite.items():
        observed = {
            kind
            for entry in entries
            for kind in intended_kinds(cast("JsonObject", entry["expected"]))
        }
        results[suite] = {
            "suite": suite,
            "kind": "misconfiguration",
            "spec_version": spec_version,
            "engine_version": engine_version,
            "doc": SUITE_DOCS[suite],
            "kinds": _kinds_block(suite, observed),
            "cases": entries,
        }
    return results


async def check_misconfiguration_case(
    suite: str, case: MisconfigurationCase
) -> str | None:
    observed = await run_misconfiguration_case(suite, case["input"])
    expected = case["expected"]
    for key in ("raises", "reported", "fatal"):
        if observed[key] != expected[key]:
            return (
                f"{suite}/{case['id']}: {key} differs: want {expected[key]!r}, "
                f"got {observed[key]!r}"
            )
    return None
