import logging
from collections.abc import Callable
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

BODY_LIMIT = 262144
RAISED_FILE_LIMIT = 1_000_000
SMALL_FILE_LIMIT = 1024
BOUNDARY = "wp251boundary"
MULTIPART = f"multipart/form-data; boundary={BOUNDARY}"
_PAYLOAD = "1' UNION SELECT password FROM users--"


class _BoundedRequest(SyncMockGuardRequest):
    def read_body_prefix(self, max_bytes: int) -> bytes:
        return self._body[:max_bytes]


def _part(name: str, value: str) -> str:
    return (
        f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'
        f"{value}\r\n"
    )


def _multipart_with_attack_at(offset: int) -> bytes:
    pad = _part("pad", "A" * offset)
    return (pad + _part("comment", _PAYLOAD) + f"--{BOUNDARY}--\r\n").encode()


def _json_with_attack_at(offset: int) -> bytes:
    return ('{"pad": "' + "A" * offset + '", "comment": "' + _PAYLOAD + '"}').encode()


def _request(
    body: bytes, content_type: str, route_config: RouteConfig | None = None
) -> _BoundedRequest:
    request = _BoundedRequest(
        path="/upload",
        method="POST",
        headers={"content-length": str(len(body)), "content-type": content_type},
        body_content=body,
    )
    request.state.client_ip = "203.0.113.9"
    request.state.route_config = route_config
    return request


def _config(**fields: int | bool) -> SyncSecurityConfig:
    config = SyncSecurityConfig(enable_redis=False, **fields)
    sus_patterns_handler.configure(config)
    return config


def _check(config: SyncSecurityConfig) -> tuple[SuspiciousActivityCheck, MagicMock]:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("test_file_inspect_limit")
    middleware.suspicious_request_counts = {}
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(
        side_effect=lambda status_code, default_message: MagicMock(
            status_code=status_code
        )
    )
    middleware.route_resolver.should_bypass_check = lambda *_: False
    return SuspiciousActivityCheck(middleware), middleware


def test_default_file_limit_is_the_named_constant_equal_to_the_body_limit() -> None:
    from guard_core.sync.handlers.suspatterns_handler import (
        _DEFAULT_MAX_FILE_INSPECT_BYTES,
    )

    assert SyncSecurityConfig().detection_max_file_inspect_bytes == (
        _DEFAULT_MAX_FILE_INSPECT_BYTES
    )
    assert _DEFAULT_MAX_FILE_INSPECT_BYTES == BODY_LIMIT


def test_the_full_scan_window_covers_the_larger_of_the_two_limits() -> None:
    _config(detection_max_file_inspect_bytes=RAISED_FILE_LIMIT)
    raised = sus_patterns_handler._preprocessor
    _config()
    default = sus_patterns_handler._preprocessor

    assert raised is not None
    assert raised._MAX_FULL_SCAN_BYTES == RAISED_FILE_LIMIT
    assert default is not None
    assert default._MAX_FULL_SCAN_BYTES == BODY_LIMIT


@pytest.mark.parametrize("bound", [1023, 10485761])
def test_the_file_limit_has_the_bounds_of_the_body_limit(bound: int) -> None:
    with pytest.raises(ValueError):
        SyncSecurityConfig(detection_max_file_inspect_bytes=bound)


def test_multipart_past_the_body_limit_is_scanned_under_a_raised_file_limit() -> None:
    body = _multipart_with_attack_at(BODY_LIMIT + 1024)
    assert len(body) > BODY_LIMIT + 1

    raised = detect_penetration_attempt(
        _request(body, MULTIPART),
        _config(detection_max_file_inspect_bytes=RAISED_FILE_LIMIT),
    )
    default = detect_penetration_attempt(_request(body, MULTIPART), _config())

    assert raised.is_threat is True
    assert raised.body_read_error is None
    assert default.is_threat is False
    assert default.body_read_error == "failed"


def test_json_of_the_same_size_is_still_refused_under_fail_secure() -> None:
    body = _json_with_attack_at(BODY_LIMIT + 1024)
    config = _config(detection_max_file_inspect_bytes=RAISED_FILE_LIMIT)

    result = detect_penetration_attempt(_request(body, "application/json"), config)
    check, middleware = _check(config)
    response = check.check(_request(body, "application/json"))

    assert result.is_threat is False
    assert result.body_read_error == "failed"
    assert response is not None
    assert response.status_code == 400
    assert middleware.suspicious_request_counts == {}


def test_multipart_past_the_file_limit_gets_the_past_the_limit_outcome() -> None:
    body = _multipart_with_attack_at(SMALL_FILE_LIMIT * 4)
    config = _config(detection_max_file_inspect_bytes=SMALL_FILE_LIMIT)

    result = detect_penetration_attempt(_request(body, MULTIPART), config)
    json_result = detect_penetration_attempt(
        _request(_json_with_attack_at(SMALL_FILE_LIMIT * 4), "application/json"),
        config,
    )

    assert result.is_threat is False
    assert result.body_read_error == "failed"
    assert json_result.is_threat is True
    assert json_result.body_read_error is None


def test_multipart_past_the_file_limit_answers_400_without_a_strike() -> None:
    body = _multipart_with_attack_at(SMALL_FILE_LIMIT * 4)
    check, middleware = _check(
        _config(detection_max_file_inspect_bytes=SMALL_FILE_LIMIT)
    )

    response = check.check(_request(body, MULTIPART))

    assert response is not None
    assert response.status_code == 400
    event = middleware.event_bus.send_middleware_event.call_args.kwargs
    assert event["event_type"] == EVENT_SUSPICIOUS_REQUEST
    assert event["action_taken"] == "request_blocked"
    assert middleware.suspicious_request_counts == {}


def test_multipart_past_the_file_limit_passes_without_fail_secure() -> None:
    body = _multipart_with_attack_at(SMALL_FILE_LIMIT * 4)
    check, middleware = _check(
        _config(detection_max_file_inspect_bytes=SMALL_FILE_LIMIT, fail_secure=False)
    )

    response = check.check(_request(body, MULTIPART))

    assert response is None
    event = middleware.event_bus.send_middleware_event.call_args.kwargs
    assert event["action_taken"] == "logged_only"
    assert middleware.suspicious_request_counts == {}


@pytest.mark.parametrize(
    ("content_type", "builder"),
    [
        (MULTIPART, _multipart_with_attack_at),
        ("application/json", _json_with_attack_at),
    ],
)
def test_route_max_request_size_above_the_applicable_limit_is_used(
    content_type: str, builder: Callable[[int], bytes]
) -> None:
    body = builder(SMALL_FILE_LIMIT * 4)
    route_config = RouteConfig()
    route_config.max_request_size = len(body)
    config = _config(
        detection_max_file_inspect_bytes=SMALL_FILE_LIMIT,
        detection_max_body_inspect_bytes=SMALL_FILE_LIMIT,
    )

    raised = detect_penetration_attempt(
        _request(body, content_type, route_config), config, route_config
    )
    sibling = detect_penetration_attempt(
        _request(body, content_type, RouteConfig()), config, RouteConfig()
    )

    assert raised.is_threat is True
    assert raised.body_read_error is None
    assert sibling.is_threat is False
    assert sibling.body_read_error == "failed"
