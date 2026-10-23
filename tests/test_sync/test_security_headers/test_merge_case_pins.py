from collections.abc import Iterator, MutableMapping
from typing import cast
from unittest.mock import MagicMock

from guard_core.models import SecurityConfig
from guard_core.sync.core.events.metrics import MetricsCollector
from guard_core.sync.core.responses.context import ResponseContext
from guard_core.sync.core.responses.factory import ErrorResponseFactory
from tests.test_sync.conftest import MockGuardResponse, MockGuardResponseFactory


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


def _factory(**security_headers: object) -> ErrorResponseFactory:
    config = SecurityConfig(
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


def _spellings(headers: MutableMapping[str, str], lowered: str) -> list[str]:
    return [name for name in headers if name.lower() == lowered]


def test_default_loses_to_a_response_header_in_another_case() -> None:
    response = MockGuardResponse(
        "ok", 200, {"x-frame-options": "DENY", "content-type": "text/html"}
    )
    result = _factory().apply_security_headers(response, "/x")
    assert _spellings(result.headers, "x-frame-options") == ["x-frame-options"]
    assert result.headers["x-frame-options"] == "DENY"
    assert result.headers["X-Content-Type-Options"] == "nosniff"


def test_forced_header_replaces_every_other_case_once() -> None:
    response = MockGuardResponse(
        "ok", 200, {"x-custom": "app", "X-CUSTOM": "app2", "X-Custom": "app3"}
    )
    factory = _factory(custom={"X-Custom": "guard"})
    result = factory.apply_security_headers(response, "/x")
    assert _spellings(result.headers, "x-custom") == ["X-Custom"]
    assert result.headers["X-Custom"] == "guard"


def test_forced_header_present_only_in_another_case_is_replaced() -> None:
    response = MockGuardResponse("ok", 200, {"x-custom": "app"})
    factory = _factory(custom={"X-Custom": "guard"})
    result = factory.apply_security_headers(response, "/x")
    assert _spellings(result.headers, "x-custom") == ["X-Custom"]
    assert result.headers["X-Custom"] == "guard"


def test_configured_names_that_differ_only_in_case_keep_one_winner() -> None:
    factory = _factory(custom={"x-frame-options": "ALLOW"})
    response = MockGuardResponse("ok", 200, {"X-FRAME-OPTIONS": "app"})
    result = factory.apply_security_headers(response, "/x")
    assert _spellings(result.headers, "x-frame-options") == ["x-frame-options"]
    assert result.headers["x-frame-options"] == "ALLOW"


def test_case_insensitive_foreign_store_keeps_app_value_and_adds_defaults() -> None:
    store = _CaseInsensitiveHeaders({"x-frame-options": "DENY", "x-custom": "app"})
    response = MockGuardResponse("ok", 200)
    response._headers = cast(dict[str, str], store)
    factory = _factory(custom={"X-Custom": "guard"})
    result = factory.apply_security_headers(response, "/x")
    assert result.headers["x-frame-options"] == "DENY"
    assert result.headers["X-Custom"] == "guard"
    assert result.headers["X-Content-Type-Options"] == "nosniff"
    assert len(result.headers) == len(set(name.lower() for name in result.headers))
