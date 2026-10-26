import subprocess
import sys

from guard_core.detection_engine.compiler import PatternCompiler
from guard_core.handlers.suspatterns_handler import SusPatternsManager

# Hostile values for the UNION SELECT row that accepts bounded comments between and
# after the keywords (WP134): runs of comments in the gaps and after SELECT, ending in
# a character the row does not accept, run in a child process with a wall bound so a
# backtracking blow-up fails the test instead of spinning.
_CHILD = """
import re
import time

from guard_core.handlers.suspatterns_handler import SusPatternsManager

rows = [
    pattern
    for pattern, _contexts, _category in SusPatternsManager._pattern_definitions
    if pattern.startswith("(?i)UNION(?:")
]
assert len(rows) == 1
row = re.compile(rows[0])
for unit in ("/**/", "/*a*/ ", "/* x */", "/*", "*/", "/", " "):
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
"""
_LINEAR_BOUND_SECONDS = 0.5
_CHILD_WALL_SECONDS = 60


def _comment_gap_row() -> str:
    return next(
        pattern
        for pattern, _contexts, _category in SusPatternsManager._pattern_definitions
        if pattern.startswith("(?i)UNION(?:")
    )


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
    timings = [float(line) for line in child.stdout.splitlines()]
    assert len(timings) == 7 * 2 * 4
    assert max(timings) < _LINEAR_BOUND_SECONDS


def test_the_pattern_safety_validator_accepts_the_comment_gap_row() -> None:
    is_safe, reason = PatternCompiler().validate_pattern_safety(_comment_gap_row())
    assert is_safe is True, reason
