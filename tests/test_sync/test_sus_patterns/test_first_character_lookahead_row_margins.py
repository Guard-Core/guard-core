import itertools
import re
import time
from collections.abc import Callable

import pytest

from guard_core.sync.detection_engine import _redos_cost_arbiter as arbiter
from guard_core.sync.detection_engine._redos_cpu_budget import ReachProbeCpuBudget
from guard_core.sync.detection_engine._redos_repeat_alphabet import (
    _has_large_bounded_repeat,
)
from guard_core.sync.detection_engine._redos_structural_prefilters import (
    _first_structural_safety_violation,
)
from guard_core.sync.detection_engine._redos_work_counter import WORK_COUNTER_SOURCE
from guard_core.sync.handlers.suspatterns_handler import (
    _BUILTIN_PATTERN_COMPILE_FLAGS,
    SusPatternsManager,
)

_RECON_LOOKAHEAD = "(?=[ajscdliwne])"
_CHAIN_LOOKAHEAD = "(?=[_abcdefhikmpstuw])"
_PROBE_UNITS = 16000
_CPU_SAMPLES = 15
_SHARE_BAR = 0.5
_WORK_RATIO_BAR = 0.8


def _row_starting_with(prefix: str) -> str:
    (row,) = [
        pattern
        for pattern, _context, _name in SusPatternsManager._pattern_definitions
        if pattern.startswith(prefix)
    ]
    return row


def _recon_asp_row() -> str:
    (row,) = [
        pattern
        for pattern, _context, _name in SusPatternsManager._pattern_definitions
        if "(?:asp|aspx|j(?:s[pa]|html)|shtml|c(?:fm|gi|er)|do|lua|inc" in pattern
    ]
    return row


def _tmp_probe_chain_row() -> str:
    return _row_starting_with(r"\A[/\\]?(?:tmp[/\\]")


def _without(row: str, lookahead: str) -> str:
    assert lookahead in row
    return row.replace(lookahead, "", 1)


def _work_of(compiled: re.Pattern[str], probe: str) -> float:
    namespace: dict[str, object] = {"re": re}
    exec(WORK_COUNTER_SOURCE, namespace)
    build_work_counter = namespace["build_work_counter"]
    assert callable(build_work_counter)
    counter = build_work_counter()
    if callable(counter):
        return float(counter(compiled, probe))
    samples = []
    for _ in range(_CPU_SAMPLES):
        start = time.process_time()
        compiled.search(probe)
        samples.append(time.process_time() - start)
    return min(samples)


def _gate_share(pattern: str) -> float:
    flags = arbiter._DEFAULT_PATTERN_FLAGS
    deadline = (
        arbiter.time.thread_time() + arbiter._REACH_PROBE_DEADLINE_SCALE_CEILING_SECONDS
    )
    builders = arbiter._reach_probe_candidate_builders(pattern, flags, deadline)
    worst = 0.0
    for _probes, samples, load_factor in arbiter._timed_probe_results(
        pattern,
        builders,
        arbiter._PATTERN_SAFETY_DEFAULT_CAP,
        ReachProbeCpuBudget(240.0),
        flags,
        _first_structural_safety_violation(pattern),
        _has_large_bounded_repeat(pattern, flags),
    ):
        if samples is None:
            continue
        _over, extrapolated, *_rest = arbiter._reach_probe_verdict_from_samples(
            samples, arbiter._PATTERN_SAFETY_DEFAULT_CAP, load_factor
        )
        worst = max(worst, extrapolated)
    return worst / arbiter._REACH_PROBE_BUDGET_SECONDS


def _same_language(old: str, new: str, alphabet: str, extra: list[str]) -> None:
    old_compiled = re.compile(old, _BUILTIN_PATTERN_COMPILE_FLAGS)
    new_compiled = re.compile(new, _BUILTIN_PATTERN_COMPILE_FLAGS)
    inputs = [
        "".join(letters)
        for length in range(7)
        for letters in itertools.product(alphabet, repeat=length)
    ] + extra
    for text in inputs:
        old_match, new_match = old_compiled.search(text), new_compiled.search(text)
        assert (old_match is None) == (new_match is None), text
        if old_match is not None and new_match is not None:
            assert old_match.span() == new_match.span(), text
            assert old_match.groupdict() == new_match.groupdict(), text


@pytest.mark.redos_timing
@pytest.mark.parametrize(
    ("row", "lookahead", "unit"),
    [
        pytest.param(_recon_asp_row, _RECON_LOOKAHEAD, ".x", id="recon-asp"),
        pytest.param(
            _tmp_probe_chain_row, _CHAIN_LOOKAHEAD, "x/", id="probe-chain-tmp"
        ),
    ],
)
def test_the_first_character_lookahead_costs_less_and_stays_under_half_the_budget(
    row: Callable[[], str], lookahead: str, unit: str
) -> None:
    new = row()
    old = _without(new, lookahead)
    probe = unit * _PROBE_UNITS
    old_work = _work_of(re.compile(old, _BUILTIN_PATTERN_COMPILE_FLAGS), probe)
    new_work = _work_of(re.compile(new, _BUILTIN_PATTERN_COMPILE_FLAGS), probe)
    assert new_work < _WORK_RATIO_BAR * old_work
    assert _gate_share(new) < _SHARE_BAR


def test_the_recon_asp_lookahead_matches_the_old_language() -> None:
    new = _recon_asp_row()
    _same_language(
        _without(new, _RECON_LOOKAHEAD),
        new,
        "asp./j%x",
        ["a/b.ASP", "x.aspx;a", "/a.jsp.", "q.ashx%00", "c.cer.png", ".x.do?q"],
    )


def test_the_tmp_probe_chain_lookahead_matches_the_old_language() -> None:
    new = _tmp_probe_chain_row()
    _same_language(
        _without(new, _CHAIN_LOOKAHEAD),
        new,
        "tmpas/.%",
        ["tmp/x.php", "a/b/config.rb", "/cron/cron.sh", "x/y/killer.php", "tmp//a"],
    )
