import re
import tracemalloc

import pytest

from guard_core._utils.pair_redaction import _PAIR_HEAD_RE
from guard_core._utils.pair_value_scan import (
    _EXTENDED_NAME_RUN_RE,
    _PAIR_START_RE,
    _SOFT_GAP_THEN_PAIR_RE,
)

_SIZE = 262144
_SLACK_BYTES = 5 * 1024 * 1024


@pytest.mark.parametrize(
    ("regex", "value"),
    [
        (_EXTENDED_NAME_RUN_RE, "a" * _SIZE),
        (_EXTENDED_NAME_RUN_RE, "+" * _SIZE),
        (_PAIR_START_RE, "a" * _SIZE + "="),
        (_SOFT_GAP_THEN_PAIR_RE, " " * 10 + "a" * _SIZE),
        (_PAIR_HEAD_RE, '"-"' + ":" * _SIZE),
        (_PAIR_HEAD_RE, "a" * _SIZE),
    ],
    ids=["name_a", "name_plus", "pair_start", "soft_gap", "head_colons", "head_name"],
)
def test_a_256_kb_run_costs_at_most_5_mb(regex: re.Pattern, value: str) -> None:
    tracemalloc.start()
    try:
        regex.match(value)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak <= _SLACK_BYTES
