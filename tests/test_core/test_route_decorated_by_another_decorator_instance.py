import logging
from typing import Any

import pytest

from guard_core.core.routing.context import RoutingContext
from guard_core.core.routing.resolver import RouteConfigResolver
from guard_core.decorators import SecurityDecorator
from guard_core.models import SecurityConfig
from tests.test_core.conftest import build_route_pipeline, send_request

_LOGGER = logging.getLogger("pipeline_harness")


def _config(**overrides: Any) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        **overrides,
    )


def _pipeline_with_foreign_route(config: SecurityConfig) -> tuple[Any, str]:
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.require_auth("bearer", verifier=lambda r, k: False)
    )
    middleware_decorator = SecurityDecorator(config)
    middleware.guard_decorator = middleware_decorator
    middleware.route_resolver = RouteConfigResolver(
        RoutingContext(
            config=config, logger=_LOGGER, guard_decorator=middleware_decorator
        )
    )
    return pipeline, route_id


async def test_strict_mode_fails_a_route_whose_config_is_unknown_to_the_decorator() -> (
    None
):
    pipeline, route_id = _pipeline_with_foreign_route(
        _config(route_resolution_strict=True)
    )

    response = await send_request(pipeline, route_id, ip="203.0.113.90")

    assert response is not None
    assert response.status_code == 500


async def test_non_strict_mode_passes_but_warns_once_per_route(
    caplog: pytest.LogCaptureFixture,
) -> None:
    pipeline, route_id = _pipeline_with_foreign_route(_config())

    with caplog.at_level(logging.WARNING):
        first = await send_request(pipeline, route_id, ip="203.0.113.91")
        second = await send_request(pipeline, route_id, ip="203.0.113.91")

    assert first is None
    assert second is None
    warnings_for_route = [
        record.getMessage()
        for record in caplog.records
        if route_id in record.getMessage() and "decorator" in record.getMessage()
    ]
    assert len(warnings_for_route) == 1
    assert "different SecurityDecorator" in warnings_for_route[0]


async def test_a_route_known_to_the_decorator_is_not_reported(
    caplog: pytest.LogCaptureFixture,
) -> None:
    pipeline, _, route_id = build_route_pipeline(
        _config(route_resolution_strict=True),
        lambda d: d.require_auth("bearer", verifier=lambda r, k: True),
    )

    with caplog.at_level(logging.WARNING):
        response = await send_request(
            pipeline,
            route_id,
            ip="203.0.113.92",
            headers={"authorization": "Bearer ok"},
        )

    assert response is None
    assert not [
        r for r in caplog.records if "different SecurityDecorator" in r.getMessage()
    ]


async def test_a_request_without_a_route_id_is_not_reported() -> None:
    pipeline, _, _ = build_route_pipeline(
        _config(route_resolution_strict=True), lambda d: d.rate_limit(5, 60)
    )

    response = await send_request(pipeline, "", ip="203.0.113.93")

    assert response is None
