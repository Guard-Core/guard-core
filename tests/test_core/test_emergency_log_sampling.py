import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.checks.implementations import emergency_mode
from guard_core.core.checks.implementations.emergency_mode import EmergencyModeCheck
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest, MockGuardResponse

_ALLOWED = "10.0.0.1"
_BLOCKED = "203.0.113.9"


def _check(**config: Any) -> tuple[EmergencyModeCheck, MagicMock]:
    middleware = MagicMock()
    middleware.config = SecurityConfig(
        enable_redis=False,
        emergency_mode=True,
        emergency_whitelist=[_ALLOWED],
        **config,
    )
    middleware.logger = logging.getLogger("guard_core.test.emergency")
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(
        side_effect=lambda status_code, default_message: MockGuardResponse(
            default_message, status_code, {}
        )
    )
    return EmergencyModeCheck(middleware), middleware


async def _hit(check: EmergencyModeCheck, ip: str) -> Any:
    request = MockGuardRequest(client_host=ip)
    request.state.client_ip = ip
    return await check.check(request)


async def test_every_blocked_request_still_gets_a_503() -> None:
    check, _ = _check()

    statuses = [(await _hit(check, _BLOCKED)).status_code for _ in range(5)]

    assert statuses == [503] * 5


async def test_the_503_carries_retry_after() -> None:
    check, _ = _check()

    response = await _hit(check, _BLOCKED)

    assert response.headers["Retry-After"] == str(emergency_mode.EMERGENCY_RETRY_AFTER)
    assert int(response.headers["Retry-After"]) > 0


async def test_blocked_requests_from_one_ip_send_one_event_per_window() -> None:
    check, middleware = _check()

    for _ in range(5):
        await _hit(check, _BLOCKED)

    assert middleware.event_bus.send_middleware_event.await_count == 1


async def test_blocked_requests_from_one_ip_log_one_line_per_window(
    caplog: pytest.LogCaptureFixture,
) -> None:
    check, _ = _check()

    with caplog.at_level("WARNING"):
        for _ in range(5):
            await _hit(check, _BLOCKED)

    lines = [r for r in caplog.records if "EMERGENCY MODE" in r.getMessage()]
    assert len(lines) == 1


async def test_a_second_blocked_ip_is_sampled_on_its_own() -> None:
    check, middleware = _check()

    for ip in (_BLOCKED, "203.0.113.10", _BLOCKED, "203.0.113.10"):
        await _hit(check, ip)

    assert middleware.event_bus.send_middleware_event.await_count == 2


async def test_the_sampled_event_is_still_an_emergency_block_event() -> None:
    check, middleware = _check()

    for _ in range(3):
        await _hit(check, _BLOCKED)

    kwargs = middleware.event_bus.send_middleware_event.await_args.kwargs
    assert kwargs["event_type"] == "emergency_mode_block"
    assert kwargs["emergency_active"] is True


async def test_the_on_block_hook_still_sees_every_blocked_request() -> None:
    hook = AsyncMock()
    check, _ = _check(on_block=hook)
    request = MockGuardRequest(client_host=_BLOCKED)
    request.state.client_ip = _BLOCKED

    for _ in range(3):
        await check.check(request)
        stash = request.state._guard_block_stash
        assert stash["reason"].startswith("[EMERGENCY MODE]")
        request.state._guard_block_stash = None


async def test_whitelisted_requests_log_one_info_line_per_window(
    caplog: pytest.LogCaptureFixture,
) -> None:
    check, _ = _check()

    with caplog.at_level("INFO"):
        for _ in range(5):
            assert await _hit(check, _ALLOWED) is None

    lines = [r for r in caplog.records if "Allowed access" in r.getMessage()]
    assert len(lines) == 1


async def test_passive_mode_samples_the_same_way() -> None:
    check, middleware = _check(passive_mode=True)

    results = [await _hit(check, _BLOCKED) for _ in range(4)]

    assert results == [None] * 4
    assert middleware.event_bus.send_middleware_event.await_count == 1
