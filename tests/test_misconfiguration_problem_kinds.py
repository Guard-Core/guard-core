import copy
import logging
import pickle
import warnings
from collections.abc import Callable
from types import SimpleNamespace
from typing import cast

import pytest
from pydantic import ValidationError

from guard_core._misconfiguration import report_misconfigurations
from guard_core._misconfiguration_kinds import (
    ALL_KINDS,
    K_RATE_LIMIT_BELOW_ONE,
    KINDS,
    MisconfigurationError,
    Problem,
    kinds_log_extra,
)
from guard_core.handlers._dynamic_rule_validation import (
    MalformedDynamicRules,
    endpoint_rate_limit_key_problems,
    find_malformed_values,
)
from guard_core.models import SecurityConfig
from guard_core.protocols.agent_protocol import DynamicRulesProtocol


def _problem(subject: str | None = None) -> Problem:
    return Problem("rate_limit is 0", kind=K_RATE_LIMIT_BELOW_ONE, subject=subject)


def test_a_problem_is_the_plain_text_it_always_was() -> None:
    problem = _problem("x")

    assert problem == "rate_limit is 0"
    assert hash(problem) == hash("rate_limit is 0")
    assert problem in frozenset({"rate_limit is 0"})
    assert (problem.kind, problem.subject, problem.severity) == (
        "rate_limit.below_one",
        "x",
        "error",
    )


def test_an_unregistered_kind_is_refused() -> None:
    with pytest.raises(ValueError, match="unregistered misconfiguration kind"):
        Problem("text", kind="made.up")


@pytest.mark.parametrize("clone", [copy.copy, copy.deepcopy])
def test_a_problem_survives_a_copy(clone: Callable[[Problem], Problem]) -> None:
    cloned = clone(_problem("x"))

    assert (type(cloned), cloned.kind, cloned.subject) == (
        Problem,
        "rate_limit.below_one",
        "x",
    )


def test_a_problem_survives_pickling() -> None:
    restored = pickle.loads(pickle.dumps(_problem("x")))

    assert (restored, restored.kind, restored.subject) == (
        "rate_limit is 0",
        "rate_limit.below_one",
        "x",
    )


def test_a_joined_string_is_plain_text_and_carries_no_kind() -> None:
    joined = "; ".join([_problem(), _problem("y")])

    assert type(joined) is str
    assert getattr(joined, "kind", None) is None
    assert type(_problem().upper()) is str


def test_malformed_rules_join_their_text_and_keep_their_kinds() -> None:
    problems: list[str] = [_problem("a"), _problem("b")]
    error = MalformedDynamicRules(problems)

    assert type(str(error)) is str
    assert [p.kind for p in error.problems if isinstance(p, Problem)] == [
        "rate_limit.below_one"
    ] * 2


def test_the_public_key_problem_function_still_returns_strings() -> None:
    problems = endpoint_rate_limit_key_problems({"/users/{id}": (5, 60)})

    assert all(isinstance(problem, str) for problem in problems)
    assert [p.kind for p in problems if isinstance(p, Problem)] == [
        "endpoint_rate_limits.router_template"
    ]


def test_find_malformed_values_keeps_the_kind_of_every_problem() -> None:
    rules = SimpleNamespace(
        ip_blacklist=["nope"],
        ip_whitelist=[],
        emergency_whitelist=[],
        global_rate_limit=0,
        global_rate_window=None,
        endpoint_rate_limits={},
        ip_ban_duration=None,
        auto_ban_duration=None,
        blocked_countries=[],
        whitelist_countries=[],
        blocked_cloud_providers=set(),
    )

    found = find_malformed_values(cast("DynamicRulesProtocol", rules))

    assert [(p.kind, p.subject) for p in found if isinstance(p, Problem)] == [
        ("dynamic_rules.ip_blacklist.invalid_entry", "nope"),
        ("dynamic_rules.global_rate_limit.below_one", None),
    ]


def test_the_raised_error_carries_every_kind_and_survives_pickling() -> None:
    error = MisconfigurationError("two", [_problem("a"), _problem("b")])
    restored = pickle.loads(pickle.dumps(error))

    assert error.kinds == ["rate_limit.below_one"] * 2
    assert (str(restored), restored.kinds) == ("two", error.kinds)


def test_the_construction_error_holds_the_error_with_its_kinds() -> None:
    with pytest.raises(ValidationError) as caught:
        SecurityConfig(
            enable_redis=False,
            ban_on_hostile_signals=False,
            fail_on_misconfiguration=True,
            rate_limit=0,
            rate_limit_window=0,
        )

    [detail] = caught.value.errors()
    raised = detail["ctx"]["error"]
    assert isinstance(raised, MisconfigurationError)
    assert isinstance(raised, ValueError)
    assert raised.kinds == ["rate_limit.below_one", "rate_limit_window.below_one"]


def test_a_log_record_carries_the_kind_and_the_subject(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        SecurityConfig(
            enable_redis=False,
            ban_on_hostile_signals=False,
            fail_on_misconfiguration=False,
            endpoint_rate_limits={"/a": (0, 60)},
        )

    [carried] = [
        r.__dict__["problems"] for r in caplog.records if "problems" in r.__dict__
    ]
    assert carried == (("endpoint_rate_limits.below_one", "/a"),)


def test_nothing_is_reported_for_no_problems_even_with_the_flag_on() -> None:
    config = SecurityConfig(
        enable_redis=False, ban_on_hostile_signals=False, fail_on_misconfiguration=True
    )

    report_misconfigurations(
        config, [], logger=logging.getLogger("guard_core"), stacklevel=1
    )


def test_the_exclude_all_paths_warning_carries_its_kind() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        SecurityConfig(
            enable_redis=False,
            ban_on_hostile_signals=False,
            fail_on_misconfiguration=False,
            exclude_all_paths=True,
        )

    [carried] = [
        w.message.args[0]
        for w in caught
        if w.category is UserWarning and isinstance(w.message, Warning)
    ]
    assert isinstance(carried, Problem)
    assert carried.kind == "exclude_all_paths.enabled"


def test_the_log_extra_helper_pairs_every_subject() -> None:
    assert kinds_log_extra("a.b", "x", None) == {
        "problems": (("a.b", "x"), ("a.b", None))
    }


def test_every_kind_is_named_setting_dot_problem() -> None:
    assert ALL_KINDS == frozenset(KINDS)
    assert all(kind.count(".") >= 1 and kind == kind.lower() for kind in ALL_KINDS)
