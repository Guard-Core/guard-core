import logging
from typing import Any
from unittest.mock import MagicMock

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.factory import build_default_pipeline
from guard_core.sync.core.routing.context import RoutingContext
from guard_core.sync.core.routing.resolver import RouteConfigResolver
from guard_core.sync.decorators import SecurityDecorator, get_route_id
from guard_core.sync.handlers.ratelimit_handler import rate_limit_handler
from tests.test_sync.conftest import MockGuardResponse

_LOGGER = logging.getLogger("test_honeypot_shares_body_prefix_with_detection")
_SQLI_BODY = b'{"q": "1 OR 1=1 UNION SELECT password FROM users--"}'


class _SingleUseState:
    def __init__(self) -> None:
        self._attrs: dict[str, Any] = {}

    def __getattr__(self, name: str) -> object:
        if name == "_attrs":
            return super().__getattribute__(name)
        return self._attrs.get(name)

    def __setattr__(self, name: str, value: object) -> None:
        if name == "_attrs":
            super().__setattr__(name, value)
        else:
            self._attrs[name] = value


class _SingleUseChunkedRequest:
    def __init__(self, path: str, body: bytes) -> None:
        self._path = path
        self._body = body
        self._consumed = False
        self.read_body_prefix_calls = 0
        self._state = _SingleUseState()

    @property
    def url_path(self) -> str:
        return self._path

    @property
    def url_scheme(self) -> str:
        return "https"

    @property
    def url_full(self) -> str:
        return f"https://test{self._path}"

    def url_replace_scheme(self, scheme: str) -> str:
        return f"{scheme}://test{self._path}"

    @property
    def method(self) -> str:
        return "POST"

    @property
    def client_host(self) -> str | None:
        return "203.0.113.90"

    @property
    def headers(self) -> dict[str, str]:
        return {"content-type": "application/json"}

    @property
    def query_params(self) -> dict[str, str]:
        return {}

    def body(self) -> bytes:
        return self.read_body_prefix(len(self._body) or 1)

    def read_body_prefix(self, max_bytes: int) -> bytes:
        self.read_body_prefix_calls += 1
        if self._consumed:
            return b""
        self._consumed = True
        return self._body[:max_bytes]

    @property
    def state(self) -> _SingleUseState:
        return self._state

    @property
    def scope(self) -> dict[str, Any]:
        return {}


def _config(**overrides: object) -> SyncSecurityConfig:
    fields: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": True,
        "enable_ip_banning": False,
    }
    fields.update(overrides)
    return SyncSecurityConfig(**fields)


def _build_middleware(
    config: SyncSecurityConfig, decorator: SecurityDecorator | None
) -> MagicMock:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = _LOGGER
    middleware.event_bus = MagicMock()
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(
        side_effect=lambda status_code, default_message: MockGuardResponse(
            default_message, status_code
        )
    )
    middleware.guard_decorator = decorator
    middleware.route_resolver = RouteConfigResolver(
        RoutingContext(config=config, logger=_LOGGER, guard_decorator=decorator)
    )
    middleware.geo_ip_handler = None
    middleware.agent_handler = None
    middleware.rate_limit_handler = rate_limit_handler(config)
    middleware.suspicious_request_counts = {}
    return middleware


def _honeypot_route(config: SyncSecurityConfig) -> tuple[SecurityDecorator, str]:
    decorator = SecurityDecorator(config)

    def sample_endpoint() -> str:
        return "ok"

    sample_endpoint.__name__ = "sample_endpoint"
    sample_endpoint.__qualname__ = "sample_endpoint"
    sample_endpoint.__module__ = __name__

    decorated = decorator.honeypot_detection(["hp_trap"])(sample_endpoint)
    route_id: str = get_route_id(decorated)
    return decorator, route_id


def test_chunked_sqli_on_a_honeypot_route_is_still_detected() -> None:
    config = _config()
    decorator, route_id = _honeypot_route(config)
    middleware = _build_middleware(config, decorator)
    pipeline = build_default_pipeline(middleware)

    request = _SingleUseChunkedRequest("/api/orders", _SQLI_BODY)
    request.state.guard_route_id = route_id

    result = pipeline.execute(request)

    assert result is not None
    assert middleware.suspicious_request_counts != {}


def test_chunked_sqli_on_a_honeypot_route_reads_the_body_stream_once() -> None:
    config = _config()
    decorator, route_id = _honeypot_route(config)
    middleware = _build_middleware(config, decorator)
    pipeline = build_default_pipeline(middleware)

    request = _SingleUseChunkedRequest("/api/orders", _SQLI_BODY)
    request.state.guard_route_id = route_id

    pipeline.execute(request)

    assert request.read_body_prefix_calls == 1


def test_chunked_sqli_without_a_honeypot_route_is_detected_as_the_control() -> None:
    config = _config()
    middleware = _build_middleware(config, None)
    pipeline = build_default_pipeline(middleware)

    request = _SingleUseChunkedRequest("/api/orders", _SQLI_BODY)

    result = pipeline.execute(request)

    assert result is not None
    assert middleware.suspicious_request_counts != {}


def test_honeypot_trap_field_still_blocks_despite_shared_body_cache() -> None:
    config = _config()
    decorator, route_id = _honeypot_route(config)
    middleware = _build_middleware(config, decorator)
    pipeline = build_default_pipeline(middleware)

    request = _SingleUseChunkedRequest("/api/orders", b'{"hp_trap": "filled-by-a-bot"}')
    request.state.guard_route_id = route_id

    result = pipeline.execute(request)

    assert result is not None
    assert result.status_code == 403
