from typing import Any, cast
from unittest.mock import Mock

import pytest

from guard_core.core.routing.context import RoutingContext
from guard_core.core.routing.resolver import RouteConfigResolver
from guard_core.decorators.base import BaseSecurityDecorator, RouteConfig


@pytest.fixture
def mock_config() -> Mock:
    config = Mock()
    config.block_cloud_providers = {"aws", "gcp"}
    return config


@pytest.fixture
def mock_guard_decorator() -> BaseSecurityDecorator:
    decorator = Mock(spec=BaseSecurityDecorator)
    route_config = RouteConfig()
    route_config.bypassed_checks = {"rate_limit"}
    decorator.get_route_config = Mock(return_value=route_config)
    return decorator


@pytest.fixture
def routing_context(
    mock_config: Mock, mock_guard_decorator: BaseSecurityDecorator
) -> RoutingContext:
    return RoutingContext(
        config=mock_config,
        logger=Mock(),
        guard_decorator=mock_guard_decorator,
    )


@pytest.fixture
def resolver(routing_context: RoutingContext) -> RouteConfigResolver:
    return RouteConfigResolver(routing_context)


def test_init(routing_context: RoutingContext) -> None:
    resolver = RouteConfigResolver(routing_context)
    assert resolver.context == routing_context


async def test_get_route_config_with_route_id(
    resolver: RouteConfigResolver,
    mock_guard_decorator: BaseSecurityDecorator,
) -> None:
    mock_request = Mock()
    mock_request.state = Mock()
    mock_request.state.guard_route_id = "test_route_id"

    result = resolver.get_route_config(mock_request)
    assert result is not None
    assert "rate_limit" in result.bypassed_checks
    cast(Mock, mock_guard_decorator.get_route_config).assert_called_once_with(
        "test_route_id"
    )


async def test_get_route_config_no_route_id(
    resolver: RouteConfigResolver,
) -> None:
    mock_request = Mock()
    mock_request.state = Mock(spec=[])

    result = resolver.get_route_config(mock_request)
    assert result is None


async def test_get_route_config_no_decorator() -> None:
    context = RoutingContext(config=Mock(), logger=Mock(), guard_decorator=None)
    resolver = RouteConfigResolver(context)

    mock_request = Mock()
    mock_request.state = Mock(spec=[])
    mock_request.state.guard_route_id = "test_route_id"

    result = resolver.get_route_config(mock_request)
    assert result is None


async def test_get_route_config_decorator_returns_none(
    resolver: RouteConfigResolver,
    mock_guard_decorator: BaseSecurityDecorator,
) -> None:
    cast(Any, mock_guard_decorator).get_route_config = Mock(return_value=None)

    mock_request = Mock()
    mock_request.state = Mock()
    mock_request.state.guard_route_id = "unknown_route"

    result = resolver.get_route_config(mock_request)
    assert result is None


def test_should_bypass_check_no_config(resolver: RouteConfigResolver) -> None:
    result = resolver.should_bypass_check("rate_limit", None)
    assert result is False


def test_should_bypass_check_specific_check(
    resolver: RouteConfigResolver,
) -> None:
    route_config = RouteConfig()
    route_config.bypassed_checks = {"rate_limit", "ip_check"}

    result = resolver.should_bypass_check("rate_limit", route_config)
    assert result is True


def test_should_bypass_check_all_checks(
    resolver: RouteConfigResolver,
) -> None:
    route_config = RouteConfig()
    route_config.bypassed_checks = {"all"}

    result = resolver.should_bypass_check("any_check", route_config)
    assert result is True


def test_should_bypass_check_not_bypassed(
    resolver: RouteConfigResolver,
) -> None:
    route_config = RouteConfig()
    route_config.bypassed_checks = {"ip_check"}

    result = resolver.should_bypass_check("rate_limit", route_config)
    assert result is False


def test_route_cloud_providers_add_to_the_global_ones(
    resolver: RouteConfigResolver,
) -> None:
    route_config = RouteConfig()
    route_config.block_cloud_providers = {"azure", "digitalocean"}

    result = resolver.get_cloud_providers_to_check(route_config)
    assert result is not None
    assert set(result) == {"aws", "gcp", "azure", "digitalocean"}


def test_get_cloud_providers_from_global_config(
    resolver: RouteConfigResolver,
) -> None:
    route_config = RouteConfig()

    result = resolver.get_cloud_providers_to_check(route_config)
    assert result is not None
    assert set(result) == {"aws", "gcp"}


def test_get_cloud_providers_none_when_no_config(
    resolver: RouteConfigResolver,
) -> None:
    result = resolver.get_cloud_providers_to_check(None)
    assert result is not None
    assert set(result) == {"aws", "gcp"}


def test_get_cloud_providers_none_when_empty() -> None:
    config = Mock()
    config.block_cloud_providers = set()
    context = RoutingContext(config=config, logger=Mock(), guard_decorator=None)
    resolver = RouteConfigResolver(context)

    result = resolver.get_cloud_providers_to_check(None)
    assert result is None
