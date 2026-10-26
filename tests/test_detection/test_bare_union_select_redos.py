import subprocess
import sys

from guard_core.detection_engine.compiler import PatternCompiler
from guard_core.handlers._suspatterns_pattern_table import BARE_UNION_SELECT_ROW

# Hostile values for the bare UNION SELECT row (WP128, CRITIC-6f F1): runs of comments
# on either side, ending in a character the row does not accept. At 7024d51b the
# comment alternative split a run of N comments in exponentially many ways (n=28 took
# 14 s of CPU), so the values run in a child process with a wall bound and the test
# fails instead of spinning.
_CHILD = """
import re
import sys
import time

from guard_core.handlers._suspatterns_pattern_table import BARE_UNION_SELECT_ROW

row = re.compile(BARE_UNION_SELECT_ROW)
for unit in ("/**/", "/*a*/ ", "/* x */", "/*", "*/", "/"):
    for n in (200, 2000):
        for value in (
            "union select" + unit * n + "x",
            unit * n + "union select x",
            "(" + unit * n + "union select" + unit * n + "x",
        ):
            start = time.perf_counter()
            row.search(value)
            print(unit.replace(" ", "_"), n, round(time.perf_counter() - start, 4))
sys.stdout.flush()
"""
_LINEAR_BOUND_SECONDS = 0.5
_CHILD_WALL_SECONDS = 60


def test_hostile_comment_runs_match_in_linear_time() -> None:
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
            f"the row did not finish in {_CHILD_WALL_SECONDS} s on a hostile run"
        ) from error
    timings = [line.split() for line in child.stdout.splitlines()]
    assert len(timings) == 6 * 2 * 3
    assert max(float(seconds) for _unit, _n, seconds in timings) < _LINEAR_BOUND_SECONDS


def test_the_pattern_safety_validator_accepts_the_bare_union_select_row() -> None:
    is_safe, reason = PatternCompiler().validate_pattern_safety(BARE_UNION_SELECT_ROW)
    assert is_safe is True, reason
