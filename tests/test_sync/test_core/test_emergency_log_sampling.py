import logging
from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.checks.implementations import emergency_mode
from guard_core.sync.core.checks.implementations.emergency_mode import (
    EmergencyModeCheck,
)
from tests.test_sync.conftest import MockGuardResponse, SyncMockGuardRequest

_ALLOWED = "10.0.0.1"
_BLOCKED = "203.0.113.9"


def _check(**config: object) -> tuple[EmergencyModeCheck, MagicMock]:
    middleware = MagicMock()
    middleware.config = SyncSecurityConfig(
        enable_redis=False,
        emergency_mode=True,
        emergency_whitelist=[_ALLOWED],
        **config,
    )
    middleware.logger = logging.getLogger("guard_core.test.emergency")
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(
        side_effect=lambda status_code, default_message: MockGuardResponse(
            default_message, status_code, {}
        )
    )
    return EmergencyModeCheck(middleware), middleware


def _hit(check: EmergencyModeCheck, ip: str) -> GuardResponse | None:
    request = SyncMockGuardRequest(client_host=ip)
    request.state.client_ip = ip
    return check.check(request)


def test_every_blocked_request_still_gets_a_503() -> None:
    check, _ = _check()

    responses = [_hit(check, _BLOCKED) for _ in range(5)]
    assert all(response is not None for response in responses)
    statuses = [response.status_code for response in responses if response]

    assert statuses == [503] * 5


def test_the_503_carries_retry_after() -> None:
    check, _ = _check()

    response = _hit(check, _BLOCKED)

    assert response is not None
    assert response.headers["Retry-After"] == str(emergency_mode.EMERGENCY_RETRY_AFTER)
    assert int(response.headers["Retry-After"]) > 0


def test_blocked_requests_from_one_ip_send_one_event_per_window() -> None:
    check, middleware = _check()

    for _ in range(5):
        _hit(check, _BLOCKED)

    assert middleware.event_bus.send_middleware_event.call_count == 1


def test_blocked_requests_from_one_ip_log_one_line_per_window(
    caplog: pytest.LogCaptureFixture,
) -> None:
    check, _ = _check()

    with caplog.at_level("WARNING"):
        for _ in range(5):
            _hit(check, _BLOCKED)

    lines = [r for r in caplog.records if "EMERGENCY MODE" in r.getMessage()]
    assert len(lines) == 1


def test_a_second_blocked_ip_is_sampled_on_its_own() -> None:
    check, middleware = _check()

    for ip in (_BLOCKED, "203.0.113.10", _BLOCKED, "203.0.113.10"):
        _hit(check, ip)

    assert middleware.event_bus.send_middleware_event.call_count == 2


def test_the_sampled_event_is_still_an_emergency_block_event() -> None:
    check, middleware = _check()

    for _ in range(3):
        _hit(check, _BLOCKED)

    kwargs = middleware.event_bus.send_middleware_event.call_args.kwargs
    assert kwargs["event_type"] == "emergency_mode_block"
    assert kwargs["emergency_active"] is True


def test_the_on_block_hook_still_sees_every_blocked_request() -> None:
    hook = MagicMock()
    check, _ = _check(on_block=hook)
    request = SyncMockGuardRequest(client_host=_BLOCKED)
    request.state.client_ip = _BLOCKED

    for _ in range(3):
        check.check(request)
        stash = request.state._guard_block_stash
        assert isinstance(stash, dict)
        assert stash["reason"].startswith("[EMERGENCY MODE]")
        request.state._guard_block_stash = None


def test_whitelisted_requests_log_one_info_line_per_window(
    caplog: pytest.LogCaptureFixture,
) -> None:
    check, _ = _check()

    with caplog.at_level("INFO"):
        for _ in range(5):
            assert _hit(check, _ALLOWED) is None

    lines = [r for r in caplog.records if "Allowed access" in r.getMessage()]
    assert len(lines) == 1


def test_passive_mode_samples_the_same_way() -> None:
    check, middleware = _check(passive_mode=True)

    results = [_hit(check, _BLOCKED) for _ in range(4)]

    assert results == [None] * 4
    assert middleware.event_bus.send_middleware_event.call_count == 1
