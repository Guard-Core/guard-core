import argparse
import concurrent.futures
import json
import os
import sys
import threading
from collections.abc import Callable
from typing import Any

import pytest

from perf_gate import callcount, compare, gate, run


def row_line(row: str, key: str, value: float) -> str:
    return "ROW " + json.dumps({"mode": "calls", "row": row, key: value})


def test_row_lines_parse_and_other_output_is_ignored() -> None:
    text = "\n".join(
        [
            "warming up",
            row_line("a", "calls_per_request", 10.5),
            row_line("b", "calls_per_request", 3),
            "",
        ]
    )
    assert compare.parse_rows(text, "calls_per_request") == {"a": 10.5, "b": 3.0}


def test_a_repeated_row_line_is_an_error() -> None:
    text = (
        row_line("a", "calls_per_request", 1)
        + "\n"
        + row_line("a", "calls_per_request", 2)
    )
    with pytest.raises(ValueError, match="printed twice"):
        compare.parse_rows(text, "calls_per_request")


def test_a_row_line_without_the_value_key_is_an_error() -> None:
    with pytest.raises(KeyError):
        compare.parse_rows(row_line("a", "other", 1), "calls_per_request")


def test_the_row_list_is_the_fifteen_rows_of_the_ledger_matrix() -> None:
    assert len(run.ALL_ROWS) == 15
    assert len(set(run.ALL_ROWS)) == 15


def test_redis_url_reaches_only_the_redis_rows() -> None:
    redis_rows = {r for r in run.ALL_ROWS if run.uses_redis(r)}
    assert "ban_check" in redis_rows
    assert "allowed-get-redis-on" in redis_rows
    assert "allowed-get-redis-off" not in redis_rows
    assert "blocked-banned-pen0-redison" in redis_rows
    assert "blocked-pattern-redisoff" not in redis_rows
    assert len(redis_rows) == 8


def test_identical_call_counts_are_a_working_gate() -> None:
    same = {"a": 100.0, "b": 2.5}
    assert compare.aa_differences(same, dict(same)) == []


def test_any_call_count_difference_in_the_a_a_breaks_the_gate() -> None:
    assert compare.aa_differences({"a": 1.0, "b": 2.0}, {"a": 1.0, "b": 2.01}) == ["b"]
    assert compare.aa_differences({"a": 1.0}, {"a": 1.0, "b": 2.0}) == ["b"]


def test_a_row_fails_when_head_calls_exceed_v440_and_not_when_equal_or_below() -> None:
    base = {"a": 10.0, "b": 10.0, "c": 10.0}
    head = {"a": 10.01, "b": 10.0, "c": 9.0}
    assert compare.calls_failures(head, base) == ["a"]


def test_percent_is_signed_against_the_base() -> None:
    assert compare.percent(110.0, 100.0) == pytest.approx(10.0)
    assert compare.percent(90.0, 100.0) == pytest.approx(-10.0)


def test_exact_rule_passes_at_or_below_and_fails_one_instruction_above() -> None:
    base = [1000.0, 1000.0]
    assert compare.instruction_verdict(base, [1000.0, 1000.0]).status == "pass"
    assert compare.instruction_verdict(base, [999.0, 1000.0]).status == "pass"
    over = compare.instruction_verdict(base, [1000.0, 1001.0])
    assert (over.status, over.rule) == ("fail", "exact")
    assert over.percent_vs_base == pytest.approx(0.1)


def test_an_identical_arm_passes_with_and_without_spread() -> None:
    exact = [500.0] * 3
    assert compare.instruction_verdict(exact, list(exact)).status == "pass"
    spread = [500.0, 501.0, 502.0, 500.0, 503.0, 501.0, 500.0, 502.0]
    verdict = compare.instruction_verdict(spread, list(spread))
    assert (verdict.status, verdict.rule) == ("pass", "disjoint")


def test_spread_rows_need_eight_runs_per_arm_before_any_verdict() -> None:
    base = [100.0, 101.0, 102.0]
    head = [200.0, 201.0, 202.0]
    verdict = compare.instruction_verdict(base, head)
    assert verdict.status == "needs_more_runs"
    assert verdict.runs_per_arm == 3


def test_spread_rows_fail_only_when_head_min_is_above_base_max() -> None:
    base = [100.0 + i % 3 for i in range(8)]
    overlapping = [101.0 + i for i in range(8)]
    assert compare.instruction_verdict(base, overlapping).status == "pass"
    above = [103.0 + i for i in range(8)]
    verdict = compare.instruction_verdict(base, above)
    assert (verdict.status, verdict.runs_per_arm) == ("fail", 8)


def test_false_alarm_rate_is_one_over_c_2k_k() -> None:
    assert compare.false_alarm_rate(8) == pytest.approx(1 / 12870)
    assert compare.false_alarm_rate(8) == pytest.approx(7.8e-5, rel=0.01)


def calls_args() -> argparse.Namespace:
    return argparse.Namespace(base="base", head="head", redis_url="redis://unused")


def fake_measure(monkeypatch: pytest.MonkeyPatch, runs: list[dict[str, float]]) -> None:
    queue = iter(runs)
    monkeypatch.setattr(gate, "measure", lambda *args, **kwargs: next(queue))


def test_a_nonzero_call_count_a_a_fails_the_job_as_gate_broken(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_measure(monkeypatch, [{"a": 100.0}, {"a": 100.5}])
    lines: list[str] = []
    assert gate.calls_part(calls_args(), ["a"], lines) == 3
    assert any("GATE BROKEN" in line for line in lines)


def test_calls_part_passes_equal_and_fails_a_row_above_v440(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_measure(monkeypatch, [{"a": 100.0}, {"a": 100.0}, {"a": 100.0}])
    assert gate.calls_part(calls_args(), ["a"], []) == 0
    fake_measure(monkeypatch, [{"a": 100.0}, {"a": 100.0}, {"a": 101.0}])
    lines: list[str] = []
    assert gate.calls_part(calls_args(), ["a"], lines) == 1
    assert any("FAIL" in line for line in lines)


HERE = os.path.dirname(__file__)


def counted_here(
    skipped: set[Any], body: Callable[[concurrent.futures.Executor], None]
) -> callcount.CallCounter:
    counter = callcount.CallCounter(skipped, None, HERE)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        barrier = threading.Barrier(2)
        for future in [executor.submit(barrier.wait) for _ in range(2)]:
            future.result()
        sys.setprofile(counter)
        try:
            body(executor)
        finally:
            sys.setprofile(None)
    return counter


def idle(executor: concurrent.futures.Executor) -> None:
    return None


def idle_baseline() -> int:
    """Counted frames of the harness itself (the body call): every pin is relative."""
    return counted_here(set(), idle).mine


def worker_only_function() -> int:
    return 1


def main_thread_function() -> int:
    return 1


def test_a_function_that_runs_only_on_a_pool_worker_counts_zero() -> None:
    ran: list[int] = []

    def body(executor: concurrent.futures.Executor) -> None:
        ran.append(executor.submit(worker_only_function).result())

    counter = counted_here(set(), body)
    assert ran == [1]
    assert counter.mine == idle_baseline()
    assert counter.total > 0


def test_the_same_function_on_the_measuring_thread_counts_once() -> None:
    def body(executor: concurrent.futures.Executor) -> None:
        main_thread_function()

    assert counted_here(set(), body).mine == idle_baseline() + 1


def test_a_skipped_frame_hides_everything_it_calls() -> None:
    def hidden() -> int:
        return main_thread_function()

    def body(executor: concurrent.futures.Executor) -> None:
        hidden()

    counter = counted_here({hidden.__code__}, body)
    assert counter.mine == idle_baseline()
