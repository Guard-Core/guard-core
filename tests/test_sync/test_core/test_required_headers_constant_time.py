import hmac
from typing import Any

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.checks.implementations import required_headers
from tests.test_sync.test_core.conftest import build_route_pipeline, send_request

SECRET = "s3cret-value"


class _RecordingAgent:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def send_event(self, event: Any) -> None:
        self.events.append(event)


def _config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
    )


def test_a_secret_header_is_compared_in_constant_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[bytes, bytes]] = []
    real = hmac.compare_digest

    def spy(a: bytes, b: bytes) -> bool:
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(required_headers.hmac, "compare_digest", spy)
    pipeline, _, route_id = build_route_pipeline(
        _config(), lambda d: d.require_headers({"X-Internal-Secret": SECRET})
    )

    good = send_request(
        pipeline, route_id, ip="203.0.113.61", headers={"X-Internal-Secret": SECRET}
    )
    bad = send_request(
        pipeline, route_id, ip="203.0.113.61", headers={"X-Internal-Secret": "nope"}
    )

    assert good is None
    assert bad is not None
    assert calls == [
        (SECRET.encode(), SECRET.encode()),
        (b"nope", SECRET.encode()),
    ]


def test_a_non_ascii_secret_compares_without_raising() -> None:
    pipeline, _, route_id = build_route_pipeline(
        _config(), lambda d: d.require_headers({"X-Internal-Secret": "clave-ñ"})
    )

    response = send_request(
        pipeline, route_id, ip="203.0.113.62", headers={"X-Internal-Secret": "clave-ñ"}
    )

    assert response is None


def test_presence_only_headers_never_compare_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def explode(a: bytes, b: bytes) -> bool:
        raise AssertionError("presence-only header compared")

    monkeypatch.setattr(required_headers.hmac, "compare_digest", explode)
    pipeline, _, route_id = build_route_pipeline(
        _config(), lambda d: d.require_headers({"X-Trace": "required"})
    )

    response = send_request(
        pipeline, route_id, ip="203.0.113.63", headers={"X-Trace": "anything"}
    )

    assert response is None
