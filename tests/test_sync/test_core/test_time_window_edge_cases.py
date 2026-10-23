from typing import cast
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.implementations.time_window import TimeWindowCheck


@pytest.fixture
def mock_middleware() -> Mock:
    config = SyncSecurityConfig()
    config.passive_mode = False

    middleware = Mock()
    middleware.config = config
    middleware.logger = MagicMock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(return_value=Mock(status_code=403))
    return middleware


@pytest.fixture
def time_window_check(mock_middleware: Mock) -> TimeWindowCheck:
    return TimeWindowCheck(mock_middleware)


def test_check_time_window_exception_handling(
    time_window_check: TimeWindowCheck,
) -> None:
    invalid_restrictions = {"invalid": "data"}

    result = time_window_check._check_time_window(invalid_restrictions)

    assert result is True
    cast(MagicMock, time_window_check.logger.error).assert_called_once()


def test_check_time_window_missing_start_key(
    time_window_check: TimeWindowCheck,
) -> None:
    incomplete_restrictions = {"end": "18:00"}

    result = time_window_check._check_time_window(incomplete_restrictions)

    assert result is True
    cast(MagicMock, time_window_check.logger.error).assert_called_once()


def test_check_time_window_missing_end_key(
    time_window_check: TimeWindowCheck,
) -> None:
    incomplete_restrictions = {"start": "09:00"}

    result = time_window_check._check_time_window(incomplete_restrictions)

    assert result is True
    cast(MagicMock, time_window_check.logger.error).assert_called_once()


def test_check_time_window_invalid_timezone_fallback(
    time_window_check: TimeWindowCheck,
) -> None:
    restrictions = {
        "start": "00:00",
        "end": "23:59",
        "timezone": "Invalid/Timezone",
    }

    result = time_window_check._check_time_window(restrictions)

    assert result is True
