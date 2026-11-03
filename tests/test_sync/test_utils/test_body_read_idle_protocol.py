import logging
import time
from collections.abc import Callable
from typing import Any, cast
from unittest.mock import MagicMock

import pytest

from guard_core.exceptions import (
    BodyReadFailedError,
    BodyReadSlotsExhaustedError,
    BodyReadStalledError,
)
from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.body_reader import (
    _read_capped_body,
    _read_capped_body_or_raise,
)
from guard_core.sync.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.sync.core.events.event_types import EVENT_SUSPICIOUS_REQUEST
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

CLIENT = "203.0.113.7"
LOGGER = "guard_core"


def _config(**overrides: object) -> SyncSecurityConfig:
    values: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": True,
        "rate_limit": 10000,
    }
    values.update(overrides)
    return SyncSecurityConfig(**values)


def _check(config: SyncSecurityConfig) -> tuple[SuspiciousActivityCheck, MagicMock]:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("test_body_read_idle_protocol")
    middleware.suspicious_request_counts = {}
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(
        side_effect=lambda status_code, default_message: MagicMock(
            status_code=status_code
        )
    )
    middleware.route_resolver.should_bypass_check = lambda *_: False
    return SuspiciousActivityCheck(middleware), middleware


def _stamp(request: SyncMockGuardRequest) -> SyncMockGuardRequest:
    request.state.client_ip = CLIENT
    request.state.route_config = None
    return request


def _post(**headers: str) -> dict[str, str]:
    return {"content-type": "text/plain", "content-length": "4", **headers}


class _IdleRequest(SyncMockGuardRequest):
    def __init__(self, outcome: object) -> None:
        super().__init__(method="POST", path="/x", headers=_post())
        self.outcome = outcome
        self.calls: list[tuple[int, float]] = []

    def read_body_prefix_until_idle(self, max_bytes: int, idle_timeout: float) -> bytes:
        self.calls.append((max_bytes, idle_timeout))
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return cast(bytes, self.outcome)


def _idle_request_class(outcome: object) -> Callable[[], _IdleRequest]:
    return lambda: _IdleRequest(outcome)


def test_an_adapter_with_the_idle_method_is_read_through_it() -> None:
    config = _config(body_read_timeout=2.5)
    request = _idle_request_class(b"idle")()

    body = _read_capped_body_or_raise(request, config)

    assert body == b"idle"
    assert request.calls == [(config.detection_max_body_inspect_bytes, 2.5)]


def test_the_idle_method_is_preferred_over_the_older_readers() -> None:
    class _AllThree(SyncMockGuardRequest):
        def __init__(self) -> None:
            super().__init__(method="POST", path="/x", headers=_post())
            self.used: list[str] = []

        def read_body_prefix_until_idle(
            self, max_bytes: int, idle_timeout: float
        ) -> bytes:
            self.used.append("idle")
            return b"idle"

        def read_body_prefix(self, max_bytes: int) -> bytes:
            self.used.append("prefix")
            return b"prefix"

        def body(self) -> bytes:
            self.used.append("body")
            return b"body"

    request = _AllThree()

    assert _read_capped_body_or_raise(request, _config()) == b"idle"
    assert request.used == ["idle"]


def test_an_adapter_with_only_the_old_prefix_method_warns_once_per_class(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class _OldPrefixOnly(SyncMockGuardRequest):
        def read_body_prefix(self, max_bytes: int) -> bytes:
            return b"old"

    config = _config()
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        first = _OldPrefixOnly(method="POST", path="/x", headers=_post())
        second = _OldPrefixOnly(method="POST", path="/x", headers=_post())
        assert _read_capped_body_or_raise(first, config) == b"old"
        assert _read_capped_body_or_raise(second, config) == b"old"

    naming = [r for r in caplog.records if "read_body_prefix_until_idle" in r.message]
    assert len(naming) == 1
    assert "_OldPrefixOnly" in naming[0].message
    assert "no idle deadline" in naming[0].message


def test_the_old_prefix_method_is_not_given_an_engine_deadline() -> None:
    class _SlowPrefix(SyncMockGuardRequest):
        def read_body_prefix(self, max_bytes: int) -> bytes:
            time.sleep(0.25)
            return b"slow"

    request = _SlowPrefix(method="POST", path="/x", headers=_post())

    result = _read_capped_body_or_raise(request, _config(body_read_timeout=0.05))

    assert result == b"slow"


def test_an_adapter_with_only_body_is_awaited_in_full_with_no_deadline(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class _BodyOnly(SyncMockGuardRequest):
        def body(self) -> bytes:
            time.sleep(0.25)
            return b"slow"

    request = _BodyOnly(method="POST", path="/x", headers=_post())

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        result = _read_capped_body_or_raise(request, _config(body_read_timeout=0.05))

    assert result == b"slow"
    assert "neither read_body_prefix_until_idle nor read_body_prefix" in caplog.text


def test_a_body_only_adapter_is_not_read_when_the_size_is_unbounded() -> None:
    class _BodyOnly(SyncMockGuardRequest):
        reads = 0

        def body(self) -> bytes:
            type(self).reads += 1
            return b"never"

    request = _BodyOnly(method="POST", path="/x", headers={})

    assert _read_capped_body_or_raise(request, _config()) is None
    assert _BodyOnly.reads == 0


def test_a_stalled_read_answers_408_with_no_strike() -> None:
    config = _config(fail_secure=True)
    check, middleware = _check(config)
    request = _stamp(_idle_request_class(BodyReadStalledError())())

    response = check.check(request)

    assert response is not None
    assert response.status_code == 408
    event = middleware.event_bus.send_middleware_event.call_args.kwargs
    assert event["event_type"] == EVENT_SUSPICIOUS_REQUEST
    assert event["action_taken"] == "request_blocked"
    assert middleware.suspicious_request_counts == {}


def test_a_failed_read_answers_400_with_no_strike() -> None:
    config = _config(fail_secure=True)
    check, middleware = _check(config)
    request = _stamp(_idle_request_class(ConnectionResetError("peer went away"))())

    response = check.check(request)

    assert response is not None
    assert response.status_code == 400
    assert middleware.suspicious_request_counts == {}


def test_a_read_that_returns_something_other_than_bytes_is_a_failure() -> None:
    check, _ = _check(_config(fail_secure=True))
    request = _stamp(_idle_request_class("not bytes")())

    response = check.check(request)

    assert response is not None
    assert response.status_code == 400


def test_without_fail_secure_a_stalled_read_is_logged_and_passes(
    caplog: pytest.LogCaptureFixture,
) -> None:
    check, middleware = _check(_config(fail_secure=False))
    request = _stamp(_idle_request_class(BodyReadStalledError())())

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        response = check.check(request)

    assert response is None
    event = middleware.event_bus.send_middleware_event.call_args.kwargs
    assert event["event_type"] == EVENT_SUSPICIOUS_REQUEST
    assert event["action_taken"] == "logged_only"
    assert middleware.suspicious_request_counts == {}


def test_passive_mode_never_blocks_a_stalled_read() -> None:
    check, middleware = _check(_config(fail_secure=True, passive_mode=True))
    request = _stamp(_idle_request_class(BodyReadStalledError())())

    assert check.check(request) is None
    event = middleware.event_bus.send_middleware_event.call_args.kwargs
    assert event["action_taken"] == "logged_only"


def test_a_stall_is_reported_on_the_detection_result_not_as_a_threat() -> None:
    request = _stamp(_idle_request_class(BodyReadStalledError())())

    result = detect_penetration_attempt(request, _config())

    assert result.is_threat is False
    assert result.body_read_error == "stalled"


def test_the_honeypot_reader_keeps_returning_none_on_a_stall(
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = _idle_request_class(BodyReadStalledError())()

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        assert _read_capped_body(request, _config()) is None

    assert "treated as unavailable" in caplog.text


def test_the_slot_wait_expiring_is_a_stall() -> None:
    assert issubclass(BodyReadSlotsExhaustedError, BodyReadStalledError)
    assert issubclass(BodyReadStalledError, Exception)
    assert issubclass(BodyReadFailedError, Exception)
    assert not issubclass(BodyReadFailedError, BodyReadStalledError)
