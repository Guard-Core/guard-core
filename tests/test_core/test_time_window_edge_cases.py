from typing import cast
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

from guard_core.core.checks.implementations.time_window import TimeWindowCheck
from guard_core.models import SecurityConfig


@pytest.fixture
def mock_middleware() -> Mock:
    config = SecurityConfig()
    config.passive_mode = False

    middleware = Mock()
    middleware.config = config
    middleware.logger = MagicMock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(return_value=Mock(status_code=403))
    return middleware


@pytest.fixture
def time_window_check(mock_middleware: Mock) -> TimeWindowCheck:
    return TimeWindowCheck(mock_middleware)


async def test_check_time_window_exception_handling(
    time_window_check: TimeWindowCheck,
) -> None:
    invalid_restrictions = {"invalid": "data"}

    result = await time_window_check._check_time_window(invalid_restrictions)

    assert result is False
    cast(MagicMock, time_window_check.logger.error).assert_called_once()


async def test_check_time_window_missing_start_key(
    time_window_check: TimeWindowCheck,
) -> None:
    incomplete_restrictions = {"end": "18:00"}

    result = await time_window_check._check_time_window(incomplete_restrictions)

    assert result is False
    cast(MagicMock, time_window_check.logger.error).assert_called_once()


async def test_check_time_window_missing_end_key(
    time_window_check: TimeWindowCheck,
) -> None:
    incomplete_restrictions = {"start": "09:00"}

    result = await time_window_check._check_time_window(incomplete_restrictions)

    assert result is False
    cast(MagicMock, time_window_check.logger.error).assert_called_once()


async def test_check_time_window_invalid_timezone_denies(
    time_window_check: TimeWindowCheck,
) -> None:
    restrictions = {
        "start": "00:00",
        "end": "23:59",
        "timezone": "Invalid/Timezone",
    }

    result = await time_window_check._check_time_window(restrictions)

    assert result is False
    cast(MagicMock, time_window_check.logger.error).assert_called_once()
