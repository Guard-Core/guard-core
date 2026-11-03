from datetime import datetime, timezone
from unittest.mock import Mock

import pytest

from guard_core.sync._utils.time_window import time_window_allows
from guard_core.sync.decorators._route_arguments import invalid_time_of_day


def _allowed_at(hour: int, minute: int, restrictions: dict[str, str]) -> bool:
    def now(zone: object) -> datetime:
        return datetime(2026, 7, 1, hour, minute, tzinfo=timezone.utc)

    return time_window_allows(restrictions, Mock(), now)


@pytest.mark.parametrize("start", ["9:00", "09:00"])
@pytest.mark.parametrize(
    ("hour", "minute", "expected"),
    [
        (3, 0, False),
        (8, 59, False),
        (9, 0, True),
        (10, 0, True),
        (17, 0, True),
        (17, 1, False),
        (20, 0, False),
    ],
)
def test_an_unpadded_hour_is_the_same_bound_as_the_padded_one(
    start: str, hour: int, minute: int, expected: bool
) -> None:
    window = {"start": start, "end": "17:00"}

    assert _allowed_at(hour, minute, window) is expected


@pytest.mark.parametrize("end", ["7:00", "07:00"])
@pytest.mark.parametrize(
    ("hour", "minute", "expected"),
    [(23, 0, True), (3, 0, True), (7, 0, True), (7, 1, False), (12, 0, False)],
)
def test_an_overnight_window_with_an_unpadded_end(
    end: str, hour: int, minute: int, expected: bool
) -> None:
    window = {"start": "22:00", "end": end}

    assert _allowed_at(hour, minute, window) is expected


def test_both_bounds_unpadded() -> None:
    window = {"start": "9:05", "end": "5:30"}

    assert _allowed_at(3, 0, window) is True
    assert _allowed_at(7, 0, window) is False
    assert _allowed_at(9, 5, window) is True


@pytest.mark.parametrize(
    "bad", ["", "9", "9:", ":30", "24:00", "9:60", "009:00", "9:000", " 9:00", "a:bc"]
)
def test_a_bad_bound_is_refused_at_decoration_and_denied_at_request_time(
    bad: str,
) -> None:
    logger = Mock()
    window = {"start": bad, "end": "17:00"}

    assert invalid_time_of_day(bad) is True
    assert _allowed_at_with(logger, window) is False
    assert logger.error.call_count == 1


def _allowed_at_with(logger: Mock, window: dict[str, str]) -> bool:
    return time_window_allows(
        window, logger, lambda zone: datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc)
    )


@pytest.mark.parametrize(
    ("text", "minutes"),
    [("0:00", 0), ("00:00", 0), ("9:00", 540), ("09:00", 540), ("23:59", 1439)],
)
def test_minutes_of_day(text: str, minutes: int) -> None:
    from guard_core.sync._utils.time_window import minutes_of_day

    assert minutes_of_day(text) == minutes
    assert invalid_time_of_day(text) is False
