import re
import time
import tracemalloc

import pytest

from guard_core.sync._utils.detection_scan import _scan_time_cap, _scan_time_spent
from guard_core.sync.handlers._suspatterns_lazy_rows import COMPILED_BUILTIN_PATTERNS
from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager

_ROW_PREFIXES = [
    r"\A[/\\]?(?:(?![\w.\-~%]*\.map(?:[/\\]|\Z))",
    r"\A[/\\]?(?:[\w.\-~%]+[/\\])*wp-content[/\\]uploads[/\\]?",
    r"\A[/\\]?(?:(?!(?:actuator|server-status|telescope)",
    r"\A[/\\]?(?P<head>(?:[\w.\-~%]+[/\\])*[\w.\-~%]*\.(?:ts|tsx|jsx|py",
    r"\A[/\\]?(?:(?!(?=[lLsScCwWdDaA])(?:(?:local_settings|settings",
    r"\A(?:(?!\n).)*etc/(?:passwd|shadow",
    r"\A[/\\](?:system|version)(?:[/\\][\w.\-~%]*)*",
    r"\A[/\\](?:(?!(?:uploads?|files|images|media|tmp)[/\\])",
]
_UNITS = ["%/", "/a", "/-/", ".git;", "x.php/"]
_MEMORY_SLACK_BYTES = 5 * 1024 * 1024
_SIZE = 262144


def _row_for(prefix: str) -> re.Pattern:
    sources = [
        source
        for source, _contexts, _category in SusPatternsManager()._pattern_definitions
        if source.startswith(prefix)
    ]
    assert sources, prefix
    return COMPILED_BUILTIN_PATTERNS[sources[0]]


def _row_peak_bytes(row: re.Pattern, content: str) -> int:
    manager = SusPatternsManager()
    tracemalloc.start()
    try:
        manager._check_regex_pattern(
            row, content, "203.0.113.9", time.monotonic(), "recon"
        )
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("unit", _UNITS)
@pytest.mark.parametrize("prefix", _ROW_PREFIXES)
def test_a_256_kb_hostile_value_costs_a_path_row_at_most_5_mb(
    prefix: str, unit: str
) -> None:
    content = (unit * (_SIZE // len(unit) + 1))[:_SIZE]
    assert _row_peak_bytes(_row_for(prefix), content) <= _MEMORY_SLACK_BYTES


def test_the_linear_finder_cpu_is_charged_to_the_scan_budget() -> None:
    hostile = ("%/" * 140000)[:_SIZE]
    cap_token = _scan_time_cap.set(60.0)
    spent_token = _scan_time_spent.set(0.0)
    try:
        SusPatternsManager()._check_regex_patterns(
            hostile, "203.0.113.9", None, "request_body"
        )
        assert _scan_time_spent.get() > 0.01
    finally:
        _scan_time_spent.reset(spent_token)
        _scan_time_cap.reset(cap_token)
