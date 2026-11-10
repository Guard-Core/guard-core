import re
from collections.abc import Iterator
from unittest.mock import patch

import pytest

from guard_core.sync._utils import detection_scan
from guard_core.sync._utils._scan_outcomes import ScanBudgetSpent
from guard_core.sync.handlers import _suspatterns_regex

_PATTERN = re.compile("a")


def _consumed_candidates(taken: list[int], total: int) -> Iterator[re.Match[str]]:
    for index, match in zip(range(total), _PATTERN.finditer("a" * total), strict=True):
        taken.append(index)
        yield match


def _first_threat_with_budget_spent(spent: bool, taken: list[int]) -> object:
    token = detection_scan._scan_time_cap.set(1.0)
    try:
        with (
            patch.object(_suspatterns_regex, "_build_regex_threat", return_value=None),
            patch.object(
                _suspatterns_regex, "_scan_time_budget_exhausted", return_value=spent
            ),
        ):
            return _suspatterns_regex._first_accepted_regex_threat(
                _consumed_candidates(taken, 5), _PATTERN, "xss", 0.0
            )
    finally:
        detection_scan._scan_time_cap.reset(token)


def test_candidate_loop_stops_at_the_first_candidate_on_a_spent_budget() -> None:
    taken: list[int] = []

    with pytest.raises(ScanBudgetSpent):
        _first_threat_with_budget_spent(True, taken)

    assert taken == [0]


def test_candidate_loop_judges_every_candidate_while_the_budget_holds() -> None:
    taken: list[int] = []

    assert _first_threat_with_budget_spent(False, taken) is None
    assert taken == [0, 1, 2, 3, 4]
