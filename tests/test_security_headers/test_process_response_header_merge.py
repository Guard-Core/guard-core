from collections.abc import Iterator, MutableMapping
from unittest.mock import AsyncMock, MagicMock

from guard_core.core.events.metrics import MetricsCollector
from guard_core.core.responses.context import ResponseContext
from guard_core.core.responses.factory import ErrorResponseFactory
from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponseHeaders
from tests.conftest import MockGuardRequest, MockGuardResponse, MockGuardResponseFactory


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


class _ForeignHeadersResponse:
    def __init__(self, items: dict[str, str]) -> None:
        self.status_code = 200
        self.body = b"ok"
        self.store = _CaseInsensitiveHeaders(items)

    @property
    def headers(self) -> GuardResponseHeaders:
        return self.store


def _factory(**security_headers: object) -> ErrorResponseFactory:
    config = SecurityConfig(
        enable_redis=False, security_headers={"enabled": True, **security_headers}
    )
    metrics = MagicMock(spec=MetricsCollector)
    metrics.collect_request_metrics = AsyncMock()
    context = ResponseContext(
        config=config,
        logger=MagicMock(),
        metrics_collector=metrics,
        response_factory=MockGuardResponseFactory(),
    )
    return ErrorResponseFactory(context)


async def test_a_dict_response_keeps_an_app_header_and_gets_the_forced_one() -> None:
    factory = _factory(csp={"default-src": ["'self'"]})
    response = MockGuardResponse(
        "ok", 200, {"content-security-policy": "old", "X-Frame-Options": "DENY"}
    )

    result = await factory.process_response(MockGuardRequest(), response, 0.0, None)

    assert result.headers["Content-Security-Policy"] == "default-src 'self'"
    assert "content-security-policy" not in result.headers
    assert result.headers["X-Frame-Options"] == "DENY"
    assert result.headers["X-Content-Type-Options"] == "nosniff"


async def test_cached_headers_without_a_plan_are_merged() -> None:
    factory = _factory()
    manager = factory.security_headers_manager
    key = manager._generate_cache_key(None, factory.context.config, manager._override)
    manager.headers_cache[key] = {"X-Plain": "1"}
    response = MockGuardResponse("ok", 200)

    result = await factory.process_response(MockGuardRequest(), response, 0.0, None)

    assert result.headers["X-Plain"] == "1"


async def test_a_response_with_a_foreign_header_container_is_merged() -> None:
    factory = _factory()
    response = _ForeignHeadersResponse({"x-frame-options": "DENY"})

    result = await factory.process_response(MockGuardRequest(), response, 0.0, None)

    assert result.headers["X-Content-Type-Options"] == "nosniff"
    assert result.headers["x-frame-options"] == "DENY"
