import subprocess
import sys

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

# LEDGER 6.211 / WP138 (D-74, D-70, D-173): values v4.4.0 flagged on the query and the
# header that landing-6d lost. A line comment marker ("#" or "--") in a keyword gap,
# and a block comment whose body holds a slash ("/*a/b*/"). "#union #select" is the
# D-70 value that stays clean.
_FLAGGED = [
    "# uniON#\nselect/*",
    "# union# select/*",
    "-- union --\nselect",
    "union #\nselect",
    "union#\nselect",
    "union#\n/**/select",
    "union /**/#\nselect",
    "union--\nall--\nselect",
    "1 UNION#\nSELECT 1,2",
    "1 UNION -- \nSELECT 1,2",
    "UNION ALL -- \n SELECT NULL",
    "x UNION /**/ -- \n /**/ SELECT 1",
    "1 UNION/*a/b*/SELECT 1",
    "1 UNION ALL/*a/b*/SELECT 1",
    "union/*http://x*/select 1,2",
    "1 UNION/*/x*/SELECT 1,2",
]
_CLEAN = [
    "#union #select",
    "trending: #union #select",
    "#union #select #from",
    "the union # select committee",
    "union-select",
    "labor union - select a representative",
]


def _request(surface: str, value: str) -> SyncMockGuardRequest:
    if surface == "query":
        return SyncMockGuardRequest(path="/x", query_params={"q": value})
    return SyncMockGuardRequest(
        path="/x", headers={"x-custom": value.replace("\n", " ").replace("\r", " ")}
    )


def _is_threat(surface: str, value: str) -> bool:
    config = SyncSecurityConfig(enable_redis=False)
    return bool(
        (detect_penetration_attempt(_request(surface, value), config)).is_threat
    )


@pytest.mark.parametrize("surface", ["query", "header"])
@pytest.mark.parametrize("value", _FLAGGED, ids=lambda value: repr(value)[:40])
def test_a_line_or_slash_comment_gap_union_select_is_flagged(
    surface: str, value: str
) -> None:
    assert _is_threat(surface, value) is True


@pytest.mark.parametrize("surface", ["query", "header"])
@pytest.mark.parametrize("value", _CLEAN, ids=lambda value: repr(value)[:40])
def test_hashtags_and_prose_around_union_select_stay_clean(
    surface: str, value: str
) -> None:
    assert _is_threat(surface, value) is False


# Hostile runs of the new gap units against both rows, in a child process with a wall
# bound: a backtracking blow-up fails the test instead of spinning, and a unit that
# cost one stack frame per iteration (80 MB for a 256 KB run of "# " before the
# maximal-run alternative) fails the memory bound.
_CHILD = """
import re
import resource
import time

from guard_core.sync.handlers._suspatterns_pattern_table import BARE_UNION_SELECT_ROW
from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager

main_rows = [
    pattern
    for pattern, _contexts, _category in SusPatternsManager._pattern_definitions
    if pattern.startswith("(?i)UNION(?:")
]
assert len(main_rows) == 1
rows = [re.compile(main_rows[0]), re.compile(BARE_UNION_SELECT_ROW)]
units = ("#", "-", "# ", "-- ", "#/**/", "/*a/b*/", "/*/x*/", "/*a/", "/*a/b", "#-")
for row in rows:
    for unit in units:
        for n in (200, 2000):
            for value in (
                "union" + unit * n + "select" + unit * n + "x",
                "union" + unit * n + "all" + unit * n + "selec",
                "union select" + unit * n + "x",
                ("union all" + unit) * n,
            ):
                start = time.perf_counter()
                row.search(value)
                print(round(time.perf_counter() - start, 4))
before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
for row in rows:
    for unit in ("# ", "-- ", "/*a/b*/"):
        n = 262144 // (2 * len(unit))
        row.search("union" + unit * n + "all" + unit * n + "select x")
after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print(after - before)
"""
_LINEAR_BOUND_SECONDS = 0.5
_CHILD_WALL_SECONDS = 120
_MEMORY_BOUND_BYTES = 20 * 1024 * 1024


def test_hostile_gap_runs_match_in_linear_time_and_bounded_memory() -> None:
    try:
        child = subprocess.run(
            [sys.executable, "-c", _CHILD],
            capture_output=True,
            text=True,
            timeout=_CHILD_WALL_SECONDS,
            check=True,
        )
    except subprocess.TimeoutExpired as error:
        raise AssertionError(
            f"a row did not finish in {_CHILD_WALL_SECONDS} s on a hostile run"
        ) from error
    *timings, growth = [float(line) for line in child.stdout.splitlines()]
    assert len(timings) == 2 * 10 * 2 * 4
    assert max(timings) < _LINEAR_BOUND_SECONDS
    ru_maxrss_unit = 1 if sys.platform == "darwin" else 1024
    assert growth * ru_maxrss_unit < _MEMORY_BOUND_BYTES
