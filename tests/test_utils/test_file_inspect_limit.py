import logging
from collections.abc import Callable
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core._utils.body_reader import _is_multipart, resolve_inspect_cap
from guard_core.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.core.events.event_types import EVENT_SUSPICIOUS_REQUEST
from guard_core.decorators.base import RouteConfig
from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

BODY_LIMIT = 262144
DEFAULT_FILE_LIMIT = 1048576
RAISED_FILE_LIMIT = 2_000_000
SMALL_FILE_LIMIT = 1024
BOUNDARY = "wp251boundary"
MULTIPART = f"multipart/form-data; boundary={BOUNDARY}"
_PAYLOAD = "1' UNION SELECT password FROM users--"


class _BoundedRequest(MockGuardRequest):
    async def read_body_prefix(self, max_bytes: int) -> bytes:
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


def _config(**fields: int | bool) -> SecurityConfig:
    config = SecurityConfig(enable_redis=False, **fields)
    sus_patterns_handler.configure(config)
    return config


def _check(config: SecurityConfig) -> tuple[SuspiciousActivityCheck, MagicMock]:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("test_file_inspect_limit")
    middleware.suspicious_request_counts = {}
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(
        side_effect=lambda status_code, default_message: MagicMock(
            status_code=status_code
        )
    )
    middleware.route_resolver.should_bypass_check = lambda *_: False
    return SuspiciousActivityCheck(middleware), middleware


def test_default_file_limit_is_the_named_constant_of_one_mebibyte() -> None:
    from guard_core.handlers.suspatterns_handler import (
        _DEFAULT_MAX_FILE_INSPECT_BYTES,
    )

    assert SecurityConfig().detection_max_file_inspect_bytes == (
        _DEFAULT_MAX_FILE_INSPECT_BYTES
    )
    assert _DEFAULT_MAX_FILE_INSPECT_BYTES == DEFAULT_FILE_LIMIT


def test_the_full_scan_window_covers_the_larger_of_the_two_limits() -> None:
    _config(detection_max_file_inspect_bytes=RAISED_FILE_LIMIT)
    raised = sus_patterns_handler._preprocessor
    _config()
    default = sus_patterns_handler._preprocessor

    assert raised is not None
    assert raised._MAX_FULL_SCAN_BYTES == RAISED_FILE_LIMIT
    assert default is not None
    assert default._MAX_FULL_SCAN_BYTES == DEFAULT_FILE_LIMIT


@pytest.mark.parametrize("bound", [1023, 10485761])
def test_the_file_limit_has_the_bounds_of_the_body_limit(bound: int) -> None:
    with pytest.raises(ValueError):
        SecurityConfig(detection_max_file_inspect_bytes=bound)


async def test_multipart_past_the_body_limit_is_scanned_under_a_raised_file_limit() -> (
    None
):
    body = _multipart_with_attack_at(BODY_LIMIT + 1024)
    assert len(body) > BODY_LIMIT + 1

    raised = await detect_penetration_attempt(
        _request(body, MULTIPART),
        _config(detection_max_file_inspect_bytes=RAISED_FILE_LIMIT),
    )
    at_the_body_limit = await detect_penetration_attempt(
        _request(body, MULTIPART), _config(detection_max_file_inspect_bytes=BODY_LIMIT)
    )

    assert raised.is_threat is True
    assert raised.body_read_error is None
    assert at_the_body_limit.is_threat is False
    assert at_the_body_limit.body_read_error == "failed"


async def test_json_of_the_same_size_is_still_refused_under_fail_secure() -> None:
    body = _json_with_attack_at(BODY_LIMIT + 1024)
    config = _config(detection_max_file_inspect_bytes=RAISED_FILE_LIMIT)

    result = await detect_penetration_attempt(
        _request(body, "application/json"), config
    )
    check, middleware = _check(config)
    response = await check.check(_request(body, "application/json"))

    assert result.is_threat is False
    assert result.body_read_error == "failed"
    assert response is not None
    assert response.status_code == 400
    assert middleware.suspicious_request_counts == {}


async def test_multipart_past_the_file_limit_gets_the_past_the_limit_outcome() -> None:
    body = _multipart_with_attack_at(SMALL_FILE_LIMIT * 4)
    config = _config(detection_max_file_inspect_bytes=SMALL_FILE_LIMIT)

    result = await detect_penetration_attempt(_request(body, MULTIPART), config)
    json_result = await detect_penetration_attempt(
        _request(_json_with_attack_at(SMALL_FILE_LIMIT * 4), "application/json"),
        config,
    )

    assert result.is_threat is False
    assert result.body_read_error == "failed"
    assert json_result.is_threat is True
    assert json_result.body_read_error is None


async def test_multipart_past_the_file_limit_answers_400_without_a_strike() -> None:
    body = _multipart_with_attack_at(SMALL_FILE_LIMIT * 4)
    check, middleware = _check(
        _config(detection_max_file_inspect_bytes=SMALL_FILE_LIMIT)
    )

    response = await check.check(_request(body, MULTIPART))

    assert response is not None
    assert response.status_code == 400
    event = middleware.event_bus.send_middleware_event.call_args.kwargs
    assert event["event_type"] == EVENT_SUSPICIOUS_REQUEST
    assert event["action_taken"] == "request_blocked"
    assert middleware.suspicious_request_counts == {}


async def test_multipart_past_the_file_limit_passes_without_fail_secure() -> None:
    body = _multipart_with_attack_at(SMALL_FILE_LIMIT * 4)
    check, middleware = _check(
        _config(detection_max_file_inspect_bytes=SMALL_FILE_LIMIT, fail_secure=False)
    )

    response = await check.check(_request(body, MULTIPART))

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
async def test_route_max_request_size_above_the_applicable_limit_is_used(
    content_type: str, builder: Callable[[int], bytes]
) -> None:
    body = builder(SMALL_FILE_LIMIT * 4)
    route_config = RouteConfig()
    route_config.max_request_size = len(body)
    config = _config(
        detection_max_file_inspect_bytes=SMALL_FILE_LIMIT,
        detection_max_body_inspect_bytes=SMALL_FILE_LIMIT,
    )

    raised = await detect_penetration_attempt(
        _request(body, content_type, route_config), config, route_config
    )
    sibling = await detect_penetration_attempt(
        _request(body, content_type, RouteConfig()), config, RouteConfig()
    )

    assert raised.is_threat is True
    assert raised.body_read_error is None
    assert sibling.is_threat is False
    assert sibling.body_read_error == "failed"


async def test_a_clean_multipart_upload_of_one_mebibyte_is_not_refused_by_default() -> (
    None
):
    body = _multipart_with_attack_at(DEFAULT_FILE_LIMIT - 2048).replace(
        _PAYLOAD.encode(), b"hello"
    )
    assert BODY_LIMIT < len(body) <= DEFAULT_FILE_LIMIT

    result = await detect_penetration_attempt(_request(body, MULTIPART), _config())

    assert result.is_threat is False
    assert result.body_read_error is None


async def test_multipart_past_the_default_file_limit_is_refused_naming_the_fix(
    caplog: pytest.LogCaptureFixture,
) -> None:
    body = _multipart_with_attack_at(DEFAULT_FILE_LIMIT + 1024)
    check, middleware = _check(_config())

    with caplog.at_level(logging.WARNING):
        response = await check.check(_request(body, MULTIPART))

    assert response is not None
    assert response.status_code == 400
    event = middleware.event_bus.send_middleware_event.call_args.kwargs
    assert event["event_type"] == EVENT_SUSPICIOUS_REQUEST
    assert event["action_taken"] == "request_blocked"
    assert (
        "the body is past the inspect cap, so only its first bytes were scanned"
        in (event["trigger_info"])
    )
    for text in (event["trigger_info"], event["reason"], caplog.text):
        assert "detection_max_file_inspect_bytes" in text
        assert "max_request_size on the route" in text
    assert "detection_max_body_inspect_bytes (1048576) reached for client" in (
        caplog.text
    )
    assert middleware.suspicious_request_counts == {}


async def test_a_body_past_the_body_limit_is_refused_naming_the_body_field() -> None:
    body = _json_with_attack_at(BODY_LIMIT + 1024)
    check, middleware = _check(_config())

    response = await check.check(_request(body, "application/json"))

    assert response is not None
    assert response.status_code == 400
    event = middleware.event_bus.send_middleware_event.call_args.kwargs
    assert (
        "raise detection_max_body_inspect_bytes, or max_request_size"
        in (event["trigger_info"])
    )
    assert "detection_max_file_inspect_bytes" not in event["trigger_info"]


@pytest.mark.parametrize(
    ("content_type", "expected"),
    [
        ("multipart/form-data; boundary=x", True),
        ("Multipart/Form-Data; boundary=x", True),
        ("  MULTIPART/FORM-DATA ;boundary=x", True),
        ("multipart/form-data", True),
        ("application/json; x=multipart/form-data", False),
        ("text/plain; multipart/form-data", False),
        ("multipart/mixed; boundary=x", False),
        ("", False),
        (None, False),
    ],
)
def test_multipart_is_decided_by_the_media_type_alone(
    content_type: str | None, expected: bool
) -> None:
    assert _is_multipart(content_type) is expected


@pytest.mark.parametrize(
    ("content_type", "expected_cap"),
    [
        ("application/json; x=multipart/form-data", BODY_LIMIT),
        ("text/plain; multipart/form-data", BODY_LIMIT),
        ("Multipart/Form-Data; boundary=x", DEFAULT_FILE_LIMIT),
    ],
)
def test_the_inspect_cap_follows_the_media_type(
    content_type: str, expected_cap: int
) -> None:
    assert resolve_inspect_cap(SecurityConfig(), None, content_type) == expected_cap
