from typing import cast
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest

from guard_core.core.bypass.context import BypassContext
from guard_core.core.bypass.handler import BypassHandler
from guard_core.core.events.metrics import MetricsCollector
from guard_core.core.responses.context import ResponseContext
from guard_core.core.responses.factory import ErrorResponseFactory
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest, MockGuardResponse, MockGuardResponseFactory


def _handler(config: SecurityConfig) -> BypassHandler:
    metrics = MagicMock(spec=MetricsCollector)
    metrics.collect_request_metrics = AsyncMock()
    factory = ErrorResponseFactory(
        ResponseContext(
            config=config,
            logger=MagicMock(),
            metrics_collector=metrics,
            response_factory=MockGuardResponseFactory(),
        )
    )
    resolver = Mock()
    resolver.should_bypass_check = Mock(return_value=True)
    event_bus = Mock()
    event_bus.send_middleware_event = AsyncMock()
    return BypassHandler(
        BypassContext(
            config=config,
            logger=Mock(),
            response_factory=factory,
            validator=Mock(),
            route_resolver=resolver,
            event_bus=event_bus,
        )
    )


async def _bypass(
    config: SecurityConfig, app_headers: dict[str, str] | None = None
) -> MockGuardResponse | None:
    downstream = MockGuardResponse("ok", 200, dict(app_headers or {}))
    call_next = AsyncMock(return_value=downstream)
    route_config = RouteConfig()
    route_config.bypassed_checks = {"all"}
    result = await _handler(config).handle_security_bypass(
        MockGuardRequest(path="/health"), call_next, route_config
    )
    return cast(MockGuardResponse | None, result)


@pytest.mark.parametrize("passive_mode", [False, True])
async def test_a_bypass_all_route_is_answered_by_the_app_in_both_modes(
    passive_mode: bool,
) -> None:
    config = SecurityConfig(enable_redis=False, passive_mode=passive_mode)

    response = await _bypass(config)

    assert response is not None
    assert response.status_code == 200


@pytest.mark.parametrize("passive_mode", [False, True])
async def test_a_bypass_all_response_carries_the_security_headers(
    passive_mode: bool,
) -> None:
    config = SecurityConfig(enable_redis=False, passive_mode=passive_mode)

    response = await _bypass(config)

    assert response is not None
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "SAMEORIGIN"
    assert "Strict-Transport-Security" in response.headers


async def test_a_bypass_all_response_keeps_the_apps_own_headers() -> None:
    config = SecurityConfig(enable_redis=False)

    response = await _bypass(config, {"x-frame-options": "DENY"})

    assert response is not None
    assert response.headers["x-frame-options"] == "DENY"


async def test_a_bypass_all_response_gets_no_headers_when_they_are_off() -> None:
    config = SecurityConfig(enable_redis=False, security_headers=None)

    response = await _bypass(config)

    assert response is not None
    assert response.headers == {}


async def test_a_passive_bypass_all_route_runs_none_of_the_pipeline() -> None:
    config = SecurityConfig(enable_redis=False, passive_mode=True)
    handler = _handler(config)
    downstream = MockGuardResponse("ok", 200)
    call_next = AsyncMock(return_value=downstream)
    route_config = RouteConfig()
    route_config.bypassed_checks = {"all"}

    result = await handler.handle_security_bypass(
        MockGuardRequest(path="/health?q=<script>alert(1)</script>"),
        call_next,
        route_config,
    )

    assert result is not None
    call_next.assert_awaited_once()
