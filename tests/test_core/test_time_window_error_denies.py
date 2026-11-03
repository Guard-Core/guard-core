from datetime import datetime, timezone
from typing import Any
from unittest.mock import Mock

import pytest

from guard_core.core.checks.implementations import time_window as check_module
from guard_core.core.checks.implementations.time_window import TimeWindowCheck
from guard_core.core.validation import validator as validator_module
from guard_core.core.validation.context import ValidationContext
from guard_core.core.validation.validator import RequestValidator
from guard_core.models import SecurityConfig

NOON = datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc)

ERROR_CASES: list[tuple[str, dict[str, Any]]] = [
    ("missing_start", {"end": "18:00"}),
    ("missing_end", {"start": "09:00"}),
    ("empty", {}),
    ("unknown_zone", {"start": "00:00", "end": "23:59", "timezone": "Mars/Olympus"}),
    ("non_string_start", {"start": None, "end": "23:59"}),
    ("non_string_end", {"start": "00:00", "end": 2359}),
]


def _both(logger: Mock) -> tuple[RequestValidator, TimeWindowCheck]:
    config = SecurityConfig(enable_redis=False)
    validator = RequestValidator(
        ValidationContext(config=config, logger=logger, event_bus=Mock())
    )
    middleware = Mock()
    middleware.config = config
    middleware.logger = logger
    check = TimeWindowCheck(middleware)
    return validator, check


def _clock(monkeypatch: pytest.MonkeyPatch, now: object) -> None:
    clock = Mock()
    clock.now = now
    for module in (check_module, validator_module):
        monkeypatch.setattr(module, "datetime", clock)


@pytest.mark.parametrize(("name", "restrictions"), ERROR_CASES)
async def test_an_evaluation_error_denies_in_check_and_legacy_validator(
    monkeypatch: pytest.MonkeyPatch, name: str, restrictions: dict[str, Any]
) -> None:
    _clock(monkeypatch, lambda tz: NOON.astimezone(tz))
    logger = Mock()
    validator, check = _both(logger)

    assert await check._check_time_window(restrictions) is False, name
    assert await validator.check_time_window(restrictions) is False, name
    assert logger.error.call_count == 2


async def test_a_raising_clock_denies_in_check_and_legacy_validator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken(tz: object) -> datetime:
        raise RuntimeError("clock failure")

    _clock(monkeypatch, broken)
    logger = Mock()
    validator, check = _both(logger)
    restrictions = {"start": "09:00", "end": "17:00"}

    assert await check._check_time_window(restrictions) is False
    assert await validator.check_time_window(restrictions) is False


async def test_the_error_log_names_the_restriction_and_error_class_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clock(monkeypatch, lambda tz: NOON.astimezone(tz))
    logger = Mock()
    _, check = _both(logger)

    await check._check_time_window(
        {"start": "09:00", "end": "17:00", "timezone": "X/Y"}
    )

    message = logger.error.call_args.args[0]
    assert "'timezone': 'X/Y'" in message
    assert "ZoneInfoNotFoundError" in message


async def test_a_valid_window_allows_and_an_outside_time_denies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clock(monkeypatch, lambda tz: NOON.astimezone(tz))
    logger = Mock()
    validator, check = _both(logger)
    inside = {"start": "09:00", "end": "17:00"}
    outside = {"start": "13:00", "end": "17:00"}

    assert await check._check_time_window(inside) is True
    assert await validator.check_time_window(inside) is True
    assert await check._check_time_window(outside) is False
    assert await validator.check_time_window(outside) is False
    logger.error.assert_not_called()
