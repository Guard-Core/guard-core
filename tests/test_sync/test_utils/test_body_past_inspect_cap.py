import logging
from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.sync.core.events.event_types import EVENT_SUSPICIOUS_REQUEST
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

CAP = 1024
CLIENT = "203.0.113.9"
_PAYLOAD = b"1' UNION SELECT password FROM users--"
_PAST_THE_CAP_PAYLOAD = b"A" * (CAP + 5000) + _PAYLOAD
_ONE_BYTE_PAST = b"A" * (CAP + 1)
_AT_THE_CAP = b"A" * CAP


class _BoundedRequest(SyncMockGuardRequest):
    def read_body_prefix(self, max_bytes: int) -> bytes:
        return self._body[:max_bytes]


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


def _request(
    body: bytes, declared: bool = True, route_config: RouteConfig | None = None
) -> _BoundedRequest:
    headers = {"content-length": str(len(body))} if declared else {}
    request = _BoundedRequest(
        path="/upload", method="POST", headers=headers, body_content=body
    )
    request.state.client_ip = CLIENT
    request.state.route_config = route_config
    return request


def _config(fail_secure: bool = True) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        detection_max_body_inspect_bytes=CAP,
        enable_redis=False,
        fail_secure=fail_secure,
    )


def _check(config: SyncSecurityConfig) -> tuple[SuspiciousActivityCheck, MagicMock]:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("test_body_past_inspect_cap")
    middleware.suspicious_request_counts = {}
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(
        side_effect=lambda status_code, default_message: MagicMock(
            status_code=status_code
        )
    )
    middleware.route_resolver.should_bypass_check = lambda *_: False
    return SuspiciousActivityCheck(middleware), middleware


@pytest.mark.parametrize("declared", [True, False])
@pytest.mark.parametrize("body", [_ONE_BYTE_PAST, _PAST_THE_CAP_PAYLOAD])
def test_a_body_past_the_cap_is_flagged_not_passed(body: bytes, declared: bool) -> None:
    result = detect_penetration_attempt(_request(body, declared), _config())

    assert result.is_threat is False
    assert result.body_read_error == "failed"
    assert "past the inspect cap" in result.body_read_detail


@pytest.mark.parametrize("declared", [True, False])
def test_a_body_past_the_cap_answers_400_with_an_event_and_no_strike(
    declared: bool,
) -> None:
    check, middleware = _check(_config(True))

    response = check.check(_request(_PAST_THE_CAP_PAYLOAD, declared))

    assert response is not None
    assert response.status_code == 400
    event = middleware.event_bus.send_middleware_event.call_args.kwargs
    assert event["event_type"] == EVENT_SUSPICIOUS_REQUEST
    assert event["action_taken"] == "request_blocked"
    assert middleware.suspicious_request_counts == {}


@pytest.mark.parametrize("declared", [True, False])
def test_a_body_past_the_cap_passes_with_an_event_without_fail_secure(
    declared: bool,
) -> None:
    check, middleware = _check(_config(False))

    response = check.check(_request(_PAST_THE_CAP_PAYLOAD, declared))

    assert response is None
    event = middleware.event_bus.send_middleware_event.call_args.kwargs
    assert event["event_type"] == EVENT_SUSPICIOUS_REQUEST
    assert event["action_taken"] == "logged_only"
    assert middleware.suspicious_request_counts == {}


@pytest.mark.parametrize("declared", [True, False])
def test_a_threat_inside_the_prefix_of_an_oversized_body_stays_a_threat(
    declared: bool,
) -> None:
    result = detect_penetration_attempt(
        _request(_PAYLOAD + _PAST_THE_CAP_PAYLOAD, declared), _config()
    )

    assert result.is_threat is True
    assert result.body_read_error is None


@pytest.mark.parametrize("declared", [True, False])
def test_a_body_at_exactly_the_cap_is_scanned_in_full_and_not_flagged(
    declared: bool,
) -> None:
    clean = detect_penetration_attempt(_request(_AT_THE_CAP, declared), _config())
    hit = detect_penetration_attempt(
        _request(_AT_THE_CAP[: CAP - len(_PAYLOAD)] + _PAYLOAD, declared), _config()
    )

    assert clean.is_threat is False
    assert clean.body_read_error is None
    assert hit.is_threat is True
    assert hit.body_read_error is None


@pytest.mark.parametrize("declared", [True, False])
def test_a_route_with_max_request_size_above_the_cap_scans_the_whole_body(
    declared: bool,
) -> None:
    route_config = RouteConfig()
    route_config.max_request_size = len(_PAST_THE_CAP_PAYLOAD)
    config = _config()

    raised = detect_penetration_attempt(
        _request(_PAST_THE_CAP_PAYLOAD, declared, route_config), config, route_config
    )
    sibling = detect_penetration_attempt(
        _request(_PAST_THE_CAP_PAYLOAD, declared, RouteConfig()), config, RouteConfig()
    )

    assert raised.is_threat is True
    assert raised.body_read_error is None
    assert sibling.is_threat is False
    assert sibling.body_read_error == "failed"


def test_a_route_max_request_size_below_the_cap_never_lowers_it() -> None:
    route_config = RouteConfig()
    route_config.max_request_size = 10
    request = _request(_AT_THE_CAP, True, route_config)

    result = detect_penetration_attempt(request, _config(), route_config)

    assert result.body_read_error is None


def test_the_default_cap_is_the_single_named_constant_and_unchanged() -> None:
    from guard_core.sync.handlers.suspatterns_handler import (
        _DEFAULT_MAX_BODY_INSPECT_BYTES,
    )

    assert SyncSecurityConfig().detection_max_body_inspect_bytes == (
        _DEFAULT_MAX_BODY_INSPECT_BYTES
    )
    assert _DEFAULT_MAX_BODY_INSPECT_BYTES == 262144
