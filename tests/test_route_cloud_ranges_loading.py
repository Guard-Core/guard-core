import asyncio
import ipaddress
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.decorators import SecurityDecorator
from guard_core.handlers.cloud_handler import cloud_handler
from guard_core.models import SecurityConfig
from tests.test_core.conftest import build_route_pipeline, send_request

AWS_RANGE = ipaddress.ip_network("198.51.100.0/24")
GCP_RANGE = ipaddress.ip_network("203.0.113.0/24")
CLIENT = "198.51.100.77"


def _config(**settings: Any) -> SecurityConfig:
    defaults: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
        "lazy_init": False,
    }
    return SecurityConfig(**{**defaults, **settings})


def _initializer(
    config: SecurityConfig, decorator: SecurityDecorator, **kw: Any
) -> HandlerInitializer:
    return HandlerInitializer(config=config, guard_decorator=decorator, **kw)


async def test_a_route_only_block_clouds_loads_its_ranges_and_blocks() -> None:
    config = _config()
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.block_clouds(["AWS"])
    )

    with patch(
        "guard_core.handlers.cloud_handler.fetch_aws_ip_ranges",
        new=AsyncMock(return_value={AWS_RANGE}),
    ) as fetch_aws:
        await _initializer(
            config, middleware.guard_decorator
        ).initialize_redis_handlers()
        response = await send_request(pipeline, route_id, ip=CLIENT)

    fetch_aws.assert_awaited_once()
    assert response is not None
    assert response.status_code == 403
    assert response.body == b"Cloud provider IP not allowed"


async def test_route_and_global_providers_are_all_loaded() -> None:
    config = _config(block_cloud_providers={"GCP"})
    _, middleware, _ = build_route_pipeline(config, lambda d: d.block_clouds(["AWS"]))

    with (
        patch(
            "guard_core.handlers.cloud_handler.fetch_aws_ip_ranges",
            new=AsyncMock(return_value={AWS_RANGE}),
        ) as fetch_aws,
        patch(
            "guard_core.handlers.cloud_handler.fetch_gcp_ip_ranges",
            new=AsyncMock(return_value=({GCP_RANGE}, {})),
        ) as fetch_gcp,
    ):
        await _initializer(
            config, middleware.guard_decorator
        ).initialize_redis_handlers()

    fetch_aws.assert_awaited_once()
    fetch_gcp.assert_awaited_once()


async def test_no_cloud_setting_loads_nothing() -> None:
    config = _config()
    _, middleware, _ = build_route_pipeline(
        config, lambda d: d.require_ip(whitelist=["10.0.0.0/8"])
    )

    with patch(
        "guard_core.handlers.cloud_handler.fetch_aws_ip_ranges", new=AsyncMock()
    ) as fetch_aws:
        await _initializer(
            config, middleware.guard_decorator
        ).initialize_redis_handlers()

    fetch_aws.assert_not_awaited()


async def test_a_route_only_block_clouds_attaches_the_agent() -> None:
    config = _config()
    _, middleware, _ = build_route_pipeline(config, lambda d: d.block_clouds(["AWS"]))
    agent = MagicMock()

    await _initializer(
        config, middleware.guard_decorator, agent_handler=agent
    ).initialize_agent_for_handlers()

    assert cloud_handler.agent_handler is agent


async def test_the_first_request_refresh_loads_route_only_providers() -> None:
    config = _config(lazy_init=True)
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.block_clouds(["AWS"])
    )
    middleware.last_cloud_ip_refresh = 0
    middleware.refresh_cloud_ip_ranges = AsyncMock()

    with patch(
        "guard_core.handlers.cloud_handler.fetch_aws_ip_ranges",
        new=AsyncMock(return_value={AWS_RANGE}),
    ) as fetch_aws:
        await send_request(pipeline, route_id, ip=CLIENT)
        task = cloud_handler._refresh_task
        assert task is not None
        await asyncio.wait_for(task, timeout=5)
        second = await send_request(pipeline, route_id, ip=CLIENT)

    fetch_aws.assert_awaited_once()
    assert second is not None
    assert second.status_code == 403


async def test_the_adapter_refresh_is_kept_when_only_global_providers_are_used() -> (
    None
):
    config = _config(lazy_init=True, block_cloud_providers={"AWS"})
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.max_request_size(10**6)
    )
    middleware.last_cloud_ip_refresh = 0
    middleware.refresh_cloud_ip_ranges = AsyncMock()

    with patch(
        "guard_core.handlers.cloud_handler.fetch_aws_ip_ranges",
        new=AsyncMock(return_value={AWS_RANGE}),
    ) as fetch_aws:
        await send_request(pipeline, route_id, ip="203.0.113.50")
        task = cloud_handler._refresh_task
        assert task is not None
        await asyncio.wait_for(task, timeout=5)

    middleware.refresh_cloud_ip_ranges.assert_awaited_once()
    fetch_aws.assert_not_awaited()
