from collections.abc import Iterator, MutableMapping
from typing import cast
from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.events.metrics import MetricsCollector
from guard_core.sync.core.responses.context import ResponseContext
from guard_core.sync.core.responses.factory import ErrorResponseFactory
from tests.test_sync.conftest import (
    MockGuardResponse,
    MockGuardResponseFactory,
    SyncMockGuardRequest,
)


class _CaseInsensitiveHeaders(MutableMapping[str, str]):
    def __init__(self, items: dict[str, str]) -> None:
        self._items = {name.lower(): (name, value) for name, value in items.items()}

    def __getitem__(self, name: str) -> str:
        return self._items[name.lower()][1]

    def __setitem__(self, name: str, value: str) -> None:
        self._items[name.lower()] = (name, value)

    def __delitem__(self, name: str) -> None:
        del self._items[name.lower()]

    def __iter__(self) -> Iterator[str]:
        return (name for name, _ in self._items.values())

    def __len__(self) -> int:
        return len(self._items)


def _response_with_store(store: MutableMapping[str, str]) -> MockGuardResponse:
    response = MockGuardResponse("ok", 200)
    response._headers = cast(dict[str, str], store)
    return response


def _factory(**security_headers: object) -> ErrorResponseFactory:
    config = SyncSecurityConfig(
        enable_redis=False, security_headers={"enabled": True, **security_headers}
    )
    metrics = MagicMock(spec=MetricsCollector)
    metrics.collect_request_metrics = MagicMock()
    context = ResponseContext(
        config=config,
        logger=MagicMock(),
        metrics_collector=metrics,
        response_factory=MockGuardResponseFactory(),
    )
    return ErrorResponseFactory(context)


def _names(response: GuardResponse) -> list[str]:
    return [name.lower() for name in response.headers.keys()]


def test_app_frame_options_survives_the_default() -> None:
    factory = _factory()
    response = MockGuardResponse("ok", 200, {"X-Frame-Options": "DENY"})

    result = factory.apply_security_headers(response, "/x")

    assert result.headers["X-Frame-Options"] == "DENY"
    assert _names(result).count("x-frame-options") == 1


def test_app_header_matches_the_default_case_insensitively() -> None:
    factory = _factory()
    response = MockGuardResponse("ok", 200, {"x-frame-options": "DENY"})

    result = factory.apply_security_headers(response, "/x")

    assert result.headers == {
        **result.headers,
        "x-frame-options": "DENY",
    }
    assert _names(result).count("x-frame-options") == 1


def test_app_cross_origin_resource_policy_survives_the_default() -> None:
    factory = _factory()
    response = MockGuardResponse(
        "ok", 200, {"Cross-Origin-Resource-Policy": "cross-origin"}
    )

    result = factory.apply_security_headers(response, "/x")

    assert result.headers["Cross-Origin-Resource-Policy"] == "cross-origin"
    assert _names(result).count("cross-origin-resource-policy") == 1


def test_defaults_the_app_did_not_set_are_still_added() -> None:
    factory = _factory()
    response = MockGuardResponse("ok", 200, {"X-Frame-Options": "DENY"})

    result = factory.apply_security_headers(response, "/x")

    assert result.headers["X-Content-Type-Options"] == "nosniff"
    assert result.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"


def test_a_changed_frame_options_overrides_the_app() -> None:
    factory = _factory(frame_options="DENY")
    response = MockGuardResponse("ok", 200, {"x-frame-options": "SAMEORIGIN"})

    result = factory.apply_security_headers(response, "/x")

    assert result.headers["X-Frame-Options"] == "DENY"
    assert _names(result).count("x-frame-options") == 1


def test_a_configured_csp_overrides_the_app() -> None:
    factory = _factory(csp={"default-src": ["'self'"]})
    response = MockGuardResponse(
        "ok", 200, {"content-security-policy": "default-src *"}
    )

    result = factory.apply_security_headers(response, "/x")

    assert result.headers["Content-Security-Policy"] == "default-src 'self'"
    assert _names(result).count("content-security-policy") == 1


def test_a_configured_hsts_overrides_the_app() -> None:
    factory = _factory(hsts={"max_age": 100, "include_subdomains": False})
    response = MockGuardResponse("ok", 200, {"strict-transport-security": "max-age=1"})

    result = factory.apply_security_headers(response, "/x")

    assert result.headers["Strict-Transport-Security"] == "max-age=100"
    assert _names(result).count("strict-transport-security") == 1


def test_a_custom_header_overrides_the_app() -> None:
    factory = _factory(custom={"X-Custom": "operator"})
    response = MockGuardResponse("ok", 200, {"x-custom": "app"})

    result = factory.apply_security_headers(response, "/x")

    assert result.headers["X-Custom"] == "operator"
    assert _names(result).count("x-custom") == 1


def test_a_custom_header_replaces_a_default_of_the_same_name() -> None:
    factory = _factory(custom={"X-Frame-Options": "ALLOW-FROM https://a.example"})
    response = MockGuardResponse("ok", 200, {"x-frame-options": "DENY"})

    result = factory.apply_security_headers(response, "/x")

    assert result.headers["X-Frame-Options"] == "ALLOW-FROM https://a.example"


@pytest.mark.parametrize("path", ["process_response", "error_response"])
def test_app_wins_on_both_response_paths(path: str) -> None:
    factory = _factory()
    response = MockGuardResponse("ok", 200, {"x-frame-options": "DENY"})

    if path == "process_response":
        result = factory.process_response(
            SyncMockGuardRequest(path="/x"), response, 0.01, None
        )
    else:
        result = factory.apply_security_headers(response)

    assert result.headers["x-frame-options"] == "DENY"
    assert _names(result).count("x-frame-options") == 1


def test_a_case_insensitive_header_store_keeps_the_apps_header() -> None:
    factory = _factory()
    response = _response_with_store(
        _CaseInsensitiveHeaders({"X-FRAME-OPTIONS": "DENY"})
    )

    result = factory.apply_security_headers(response, "/x")

    assert result.headers["x-frame-options"] == "DENY"
    assert len(list(result.headers.keys())) == len(
        {name.lower() for name in result.headers.keys()}
    )
    assert result.headers["X-Content-Type-Options"] == "nosniff"


def test_a_case_insensitive_header_store_takes_the_operator_value() -> None:
    factory = _factory(frame_options="DENY")
    response = _response_with_store(
        _CaseInsensitiveHeaders({"x-frame-options": "SAMEORIGIN"})
    )

    result = factory.apply_security_headers(response, "/x")

    assert result.headers["X-Frame-Options"] == "DENY"
    assert len(list(result.headers.keys())) == len(
        {name.lower() for name in result.headers.keys()}
    )
