import functools
from collections.abc import Callable
from typing import Any

from guard_core.models import SecurityConfig
from guard_core.sync.decorators import SecurityDecorator, get_route_decorator_config
from tests.test_sync.conftest import SyncMockGuardRequest


def _endpoint_from_factory(*guard_decorators: Callable[..., Any]) -> Any:
    def endpoint() -> str:
        return "ok"

    for guard_decorator in guard_decorators:
        endpoint = guard_decorator(endpoint)
    return endpoint


def test_endpoints_built_by_one_factory_keep_their_own_rate_limit(
    security_config: SecurityConfig,
) -> None:
    guard = SecurityDecorator(security_config)
    strict = _endpoint_from_factory(guard.rate_limit(requests=2, window=60))
    loose = _endpoint_from_factory(guard.rate_limit(requests=100, window=60))

    assert strict.__qualname__ == loose.__qualname__
    assert strict._guard_route_id != loose._guard_route_id

    request = SyncMockGuardRequest()
    request._state.guard_route_id = strict._guard_route_id
    strict_config = get_route_decorator_config(request, guard)
    assert strict_config is not None
    assert strict_config.rate_limit == 2

    request._state.guard_route_id = loose._guard_route_id
    loose_config = get_route_decorator_config(request, guard)
    assert loose_config is not None
    assert loose_config.rate_limit == 100


def test_settings_of_one_factory_built_endpoint_do_not_reach_another(
    security_config: SecurityConfig,
) -> None:
    guard = SecurityDecorator(security_config)
    admin = _endpoint_from_factory(guard.require_ip(whitelist=["10.0.0.1"]))
    health = _endpoint_from_factory(guard.bypass(["all"]))

    admin_config = guard.get_route_config(admin._guard_route_id)
    health_config = guard.get_route_config(health._guard_route_id)
    assert admin_config is not None
    assert health_config is not None
    assert not admin_config.bypassed_checks
    assert health_config.ip_whitelist is None


def test_the_first_endpoint_keeps_the_module_qualname_route_id(
    security_config: SecurityConfig,
) -> None:
    guard = SecurityDecorator(security_config)
    first = _endpoint_from_factory(guard.rate_limit(requests=2, window=60))
    second = _endpoint_from_factory(guard.rate_limit(requests=100, window=60))

    plain_id = f"{first.__module__}.{first.__qualname__}"
    assert first._guard_route_id == plain_id
    assert second._guard_route_id != plain_id
    assert guard.get_route_config(plain_id) is guard.get_route_config(
        first._guard_route_id
    )


def test_stacked_decorators_on_one_endpoint_share_one_route_config(
    security_config: SecurityConfig,
) -> None:
    guard = SecurityDecorator(security_config)
    endpoint = _endpoint_from_factory(
        guard.require_ip(whitelist=["10.0.0.1"]),
        guard.rate_limit(requests=5, window=60),
    )

    assert list(guard._route_configs) == [endpoint._guard_route_id]
    config = guard.get_route_config(endpoint._guard_route_id)
    assert config is not None
    assert config.ip_whitelist == ["10.0.0.1"]
    assert config.rate_limit == 5


def test_a_functools_wraps_wrapper_joins_the_route_config_it_wraps(
    security_config: SecurityConfig,
) -> None:
    guard = SecurityDecorator(security_config)
    inner = _endpoint_from_factory(guard.require_ip(whitelist=["10.0.0.1"]))

    @functools.wraps(inner)
    def wrapper() -> str:
        result: str = inner()
        return result

    outer = guard.rate_limit(requests=5, window=60)(wrapper)

    assert outer._guard_route_id == inner._guard_route_id
    config = guard.get_route_config(outer._guard_route_id)
    assert config is not None
    assert config.ip_whitelist == ["10.0.0.1"]
    assert config.rate_limit == 5
