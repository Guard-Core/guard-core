import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.detection_engine import ContentPreprocessor
from guard_core.sync.handlers import _suspatterns_enhanced
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.protocols.agent_protocol import SyncAgentHandlerProtocol
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

BOUNDARY = "wp255boundary"
MULTIPART = f"multipart/form-data; boundary={BOUNDARY}"
LOWERED_BODY_LIMIT = 2048
RAISED_FILE_LIMIT = 4096
DEFAULT_LIMIT = 262144


class _BoundedRequest(SyncMockGuardRequest):
    def read_body_prefix(self, max_bytes: int) -> bytes:
        return self._body[:max_bytes]


class _WindowSpy(ContentPreprocessor):
    windows: list[int] = []

    def __init__(
        self,
        max_content_length: int = 10000,
        preserve_attack_patterns: bool = True,
        agent_handler: "SyncAgentHandlerProtocol | None" = None,
        correlation_id: str | None = None,
        max_full_scan_bytes: int | None = None,
    ):
        super().__init__(
            max_content_length,
            preserve_attack_patterns,
            agent_handler,
            correlation_id,
            max_full_scan_bytes,
        )
        _WindowSpy.windows.append(self._MAX_FULL_SCAN_BYTES)


def _multipart(value: str) -> bytes:
    part = (
        f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="c"\r\n\r\n{value}\r\n'
    )
    return (part + f"--{BOUNDARY}--\r\n").encode()


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


def _windows_of_one_scan(
    request: SyncMockGuardRequest,
    route_config: RouteConfig | None = None,
    **fields: int,
) -> set[int]:
    config = SyncSecurityConfig(enable_redis=False, **fields)
    sus_patterns_handler.configure(config)
    _WindowSpy.windows = []
    result = detect_penetration_attempt(request, config, route_config)
    assert result.is_threat is False
    assert result.body_read_error is None
    return set(_WindowSpy.windows)


@pytest.fixture(autouse=True)
def _spy_on_the_preprocessor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_suspatterns_enhanced, "ContentPreprocessor", _WindowSpy)


def test_a_json_body_is_scanned_with_the_lowered_body_limit() -> None:
    body = b'{"comment": "hello"}'

    windows = _windows_of_one_scan(
        _request(body, "application/json"),
        detection_max_body_inspect_bytes=LOWERED_BODY_LIMIT,
    )

    assert windows == {LOWERED_BODY_LIMIT}


def test_a_multipart_body_is_scanned_with_the_file_limit() -> None:
    windows = _windows_of_one_scan(
        _request(_multipart("hello"), MULTIPART),
        detection_max_body_inspect_bytes=LOWERED_BODY_LIMIT,
        detection_max_file_inspect_bytes=RAISED_FILE_LIMIT,
    )

    assert windows == {RAISED_FILE_LIMIT}


def test_a_multipart_body_under_a_lowered_file_limit_gets_that_window() -> None:
    windows = _windows_of_one_scan(
        _request(_multipart("hello"), MULTIPART),
        detection_max_file_inspect_bytes=LOWERED_BODY_LIMIT,
    )

    assert windows == {LOWERED_BODY_LIMIT}


def test_a_request_without_a_body_uses_the_body_limit() -> None:
    request = SyncMockGuardRequest(path="/", method="GET", headers={})
    request.state.client_ip = "203.0.113.9"

    windows = _windows_of_one_scan(
        request,
        detection_max_body_inspect_bytes=LOWERED_BODY_LIMIT,
        detection_max_file_inspect_bytes=RAISED_FILE_LIMIT,
    )

    assert windows == {LOWERED_BODY_LIMIT}


def test_a_route_raised_past_both_limits_keeps_the_validation_cap() -> None:
    route = RouteConfig()
    route.max_request_size = 5 * DEFAULT_LIMIT

    windows = _windows_of_one_scan(
        _request(b'{"comment": "hello"}', "application/json", route), route
    )

    assert windows == {DEFAULT_LIMIT}


def test_a_route_raised_between_the_limits_gets_its_own_window() -> None:
    route = RouteConfig()
    route.max_request_size = 3000

    windows = _windows_of_one_scan(
        _request(b'{"comment": "hello"}', "application/json", route),
        route,
        detection_max_body_inspect_bytes=LOWERED_BODY_LIMIT,
        detection_max_file_inspect_bytes=RAISED_FILE_LIMIT,
    )

    assert windows == {3000}


def test_the_window_does_not_leak_into_the_next_scan() -> None:
    _windows_of_one_scan(
        _request(b'{"comment": "hello"}', "application/json"),
        detection_max_body_inspect_bytes=LOWERED_BODY_LIMIT,
    )

    windows = _windows_of_one_scan(
        _request(b'{"comment": "hello"}', "application/json")
    )

    assert windows == {DEFAULT_LIMIT}
