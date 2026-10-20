import logging
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core._utils import detection_scan, scan_remainder
from guard_core.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.core.events.event_types import EVENT_SUSPICIOUS_REQUEST
from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

CLIENT = "203.0.113.9"
_JUNK = {f"k{i}": "v" for i in range(300)}


class _ClockThatRunsOutInTheRemainder:
    """CPU time stays flat in the walk and runs out when the remainder starts."""

    def __init__(self) -> None:
        self.armed = False
        self.now = 0.0

    def cpu_seconds(self) -> float:
        if self.armed:
            self.now += 1.0
        return self.now


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


@pytest.fixture
def remainder_clock() -> Iterator[_ClockThatRunsOutInTheRemainder]:
    clock = _ClockThatRunsOutInTheRemainder()
    real_groups = scan_remainder._SurfaceRemainder.groups

    def groups(self: scan_remainder._SurfaceRemainder) -> Any:
        clock.armed = True
        return real_groups(self)

    with (
        patch.object(detection_scan, "_thread_cpu_seconds", clock.cpu_seconds),
        patch.object(scan_remainder._SurfaceRemainder, "groups", groups),
    ):
        yield clock


def _check(config: SecurityConfig) -> tuple[SuspiciousActivityCheck, MagicMock]:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("test_scan_remainder_timeout")
    middleware.suspicious_request_counts = {}
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(
        side_effect=lambda status_code, default_message: MagicMock(
            status_code=status_code
        )
    )
    middleware.route_resolver.should_bypass_check = lambda *_: False
    return SuspiciousActivityCheck(middleware), middleware


def _request(params: dict[str, str]) -> MockGuardRequest:
    request = MockGuardRequest(path="/api", query_params=params)
    request.state.client_ip = CLIENT
    request.state.route_config = None
    return request


@pytest.mark.usefixtures("remainder_clock")
async def test_a_clean_walk_then_a_remainder_timeout_is_not_a_pass() -> None:
    config = SecurityConfig(detection_max_scan_seconds=0.5, fail_secure=True)
    result = await detect_penetration_attempt(_request(_JUNK), config)
    assert result.is_threat is False
    assert result.body_read_error == "failed"
    assert "scan time budget ended" in result.body_read_detail
    assert "remaining query params" in result.body_read_detail


@pytest.mark.usefixtures("remainder_clock")
async def test_a_remainder_timeout_answers_400_with_an_event_and_no_strike() -> None:
    config = SecurityConfig(
        detection_max_scan_seconds=0.5, fail_secure=True, enable_redis=False
    )
    check, middleware = _check(config)

    response = await check.check(_request(_JUNK))

    assert response is not None
    assert response.status_code == 400
    event = middleware.event_bus.send_middleware_event.call_args.kwargs
    assert event["event_type"] == EVENT_SUSPICIOUS_REQUEST
    assert event["action_taken"] == "request_blocked"
    assert middleware.suspicious_request_counts == {}


async def test_the_walks_own_timeout_keeps_the_weighted_threat_and_the_strike() -> None:
    config = SecurityConfig(
        detection_max_scan_seconds=0.5, fail_secure=True, enable_redis=False
    )
    clock = _ClockThatRunsOutInTheRemainder()
    clock.armed = True
    check, middleware = _check(config)

    with patch.object(detection_scan, "_thread_cpu_seconds", clock.cpu_seconds):
        result = await detect_penetration_attempt(_request({"q": "hello"}), config)
        response = await check.check(_request({"q": "hello"}))

    assert result.is_threat is True
    assert result.body_read_error is None
    assert "Pattern exceeded scan time budget" in result.trigger_info
    assert response is not None
    assert response.status_code == 400
    assert middleware.suspicious_request_counts != {}
