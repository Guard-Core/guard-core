import copy
from typing import cast

import pytest
from fixture_types import JsonObject, MisconfigurationCase
from misconfiguration_cases import MisconfigurationCaseInput
from misconfiguration_harness import intended_kinds
from misconfiguration_suites import _observe_case, check_misconfiguration_case
from run_fixtures import load_index, suite_cases

from guard_core._misconfiguration_kinds import (
    ALL_KINDS,
    HOST_DEPENDENT_KINDS,
    KINDS,
)

_SUITES = [
    "misconfiguration_config",
    "misconfiguration_dynamic_rules",
    "misconfiguration_decorators",
    "misconfiguration_runtime",
]


def _cases(suite: str) -> list[MisconfigurationCase]:
    return cast("list[MisconfigurationCase]", suite_cases(suite))


def _pairs(case: MisconfigurationCase, key: str) -> list[list[str]]:
    return cast("list[list[str]]", case["expected"][key])


def test_the_four_suites_are_registered_for_python_only() -> None:
    suites = load_index()["suites"]

    for name in _SUITES:
        assert suites[name]["kind"] == "misconfiguration"
        assert suites[name]["consumers"] == ["python"]
    assert "misconfiguration" in load_index()["comparison"]


def test_every_registered_kind_but_the_host_dependent_one_has_a_single_positive() -> (
    None
):
    single = {
        kinds[0]
        for name in _SUITES
        for case in _cases(name)
        if len(kinds := intended_kinds(case["expected"])) == 1
    }

    assert single == ALL_KINDS - HOST_DEPENDENT_KINDS


def test_a_warn_kind_is_never_fatal_and_a_fatal_only_kind_is_never_reported() -> None:
    for name in _SUITES:
        for case in _cases(name):
            assert all(KINDS[k].severity == "error" for k, _ in _pairs(case, "fatal"))
            assert all(not KINDS[k].fatal_only for k, _ in _pairs(case, "reported"))
            assert case["expected"]["raises"] == bool(_pairs(case, "fatal"))


def test_each_suite_lists_the_registry_entry_of_every_kind_it_holds() -> None:
    for name in _SUITES:
        listed = cast("JsonObject", _suite_file(name)["kinds"])
        held = {k for case in _cases(name) for k, _ in _pairs(case, "reported")}
        assert held <= set(listed)
        for kind, entry in listed.items():
            assert cast("JsonObject", entry)["severity"] == KINDS[kind].severity


def _suite_file(name: str) -> JsonObject:
    import json

    from run_fixtures import CASES_DIR

    return cast("JsonObject", json.loads((CASES_DIR / f"{name}.json").read_text()))


async def test_the_replay_names_a_case_whose_expectation_drifted() -> None:
    case = copy.deepcopy(_cases("misconfiguration_config")[3])
    assert case["id"] == "rate_limit_below_one"
    case["expected"]["fatal"] = []

    failure = await check_misconfiguration_case("misconfiguration_config", case)

    assert failure is not None
    assert failure.startswith("misconfiguration_config/rate_limit_below_one: fatal")


async def test_the_generator_refuses_a_case_whose_intent_the_engine_contradicts() -> (
    None
):
    wrong: MisconfigurationCaseInput = {
        "id": "wrong_intent",
        "input": {"config": {"enable_redis": False, "rate_limit": 10}},
        "intends": ["rate_limit.below_one"],
    }

    with pytest.raises(SystemExit, match="wrong_intent"):
        await _observe_case("misconfiguration_config", wrong)
