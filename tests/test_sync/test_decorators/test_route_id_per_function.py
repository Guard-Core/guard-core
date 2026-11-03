import functools
from collections.abc import Callable
from typing import Any, Protocol

from guard_core.models import SyncSecurityConfig
from guard_core.sync.decorators import (
    SecurityDecorator,
    get_route_decorator_config,
    get_route_id,
)
from tests.test_sync.conftest import SyncMockGuardRequest


class _Endpoint(Protocol):
    __module__: str
    __qualname__: str

    def __call__(self) -> str: ...


def _endpoint_from_factory(*guard_decorators: Callable[..., Any]) -> _Endpoint:
    def endpoint() -> str:
        return "ok"

    for guard_decorator in guard_decorators:
        endpoint = guard_decorator(endpoint)
    return endpoint


def test_endpoints_built_by_one_factory_keep_their_own_rate_limit(
    security_config: SyncSecurityConfig,
) -> None:
    guard = SecurityDecorator(security_config)
    strict = _endpoint_from_factory(guard.rate_limit(requests=2, window=60))
    loose = _endpoint_from_factory(guard.rate_limit(requests=100, window=60))

    assert strict.__qualname__ == loose.__qualname__
    assert get_route_id(strict) != get_route_id(loose)

    request = SyncMockGuardRequest()
    request._state.guard_route_id = get_route_id(strict)
    strict_config = get_route_decorator_config(request, guard)
    assert strict_config is not None
    assert strict_config.rate_limit == 2

    request._state.guard_route_id = get_route_id(loose)
    loose_config = get_route_decorator_config(request, guard)
    assert loose_config is not None
    assert loose_config.rate_limit == 100


def test_settings_of_one_factory_built_endpoint_do_not_reach_another(
    security_config: SyncSecurityConfig,
) -> None:
    guard = SecurityDecorator(security_config)
    admin = _endpoint_from_factory(guard.require_ip(whitelist=["10.0.0.1"]))
    health = _endpoint_from_factory(guard.bypass(["all"]))

    admin_config = guard.get_route_config(get_route_id(admin))
    health_config = guard.get_route_config(get_route_id(health))
    assert admin_config is not None
    assert health_config is not None
    assert not admin_config.bypassed_checks
    assert health_config.ip_whitelist is None


def test_the_first_endpoint_keeps_the_module_qualname_route_id(
    security_config: SyncSecurityConfig,
) -> None:
    guard = SecurityDecorator(security_config)
    first = _endpoint_from_factory(guard.rate_limit(requests=2, window=60))
    second = _endpoint_from_factory(guard.rate_limit(requests=100, window=60))

    plain_id = f"{first.__module__}.{first.__qualname__}"
    assert get_route_id(first) == plain_id
    assert get_route_id(second) != plain_id
    assert guard.get_route_config(plain_id) is guard.get_route_config(
        get_route_id(first)
    )


def test_stacked_decorators_on_one_endpoint_share_one_route_config(
    security_config: SyncSecurityConfig,
) -> None:
    guard = SecurityDecorator(security_config)
    endpoint = _endpoint_from_factory(
        guard.require_ip(whitelist=["10.0.0.1"]),
        guard.rate_limit(requests=5, window=60),
    )

    assert list(guard._route_configs) == [get_route_id(endpoint)]
    config = guard.get_route_config(get_route_id(endpoint))
    assert config is not None
    assert config.ip_whitelist == ["10.0.0.1"]
    assert config.rate_limit == 5


def test_a_functools_wraps_wrapper_joins_the_route_config_it_wraps(
    security_config: SyncSecurityConfig,
) -> None:
    guard = SecurityDecorator(security_config)
    inner = _endpoint_from_factory(guard.require_ip(whitelist=["10.0.0.1"]))

    @functools.wraps(inner)
    def wrapper() -> str:
        result: str = inner()
        return result

    outer = guard.rate_limit(requests=5, window=60)(wrapper)

    assert get_route_id(outer) == get_route_id(inner)
    config = guard.get_route_config(get_route_id(outer))
    assert config is not None
    assert config.ip_whitelist == ["10.0.0.1"]
    assert config.rate_limit == 5


def test_a_stamped_route_id_is_not_reused_across_decorator_instances(
    security_config: SyncSecurityConfig,
) -> None:
    guard_a = SecurityDecorator(security_config)
    guard_b = SecurityDecorator(security_config)
    first = _endpoint_from_factory(guard_a.rate_limit(requests=2, window=60))
    second = _endpoint_from_factory(guard_b.bypass(["all"]))

    assert first.__qualname__ == second.__qualname__

    # Cross-instance reuse of a stamped id must not select the other
    # function's config: decorating first with guard_b assigns first its
    # own config in guard_b instead of joining second's.
    redecorated = guard_b.require_ip(whitelist=["10.0.0.1"])(first)

    first_config = guard_b.get_route_config(get_route_id(redecorated))
    second_config = guard_b.get_route_config(get_route_id(second))
    assert first_config is not None
    assert second_config is not None
    assert first_config.ip_whitelist == ["10.0.0.1"]
    assert second_config.bypassed_checks == {"all"}
    assert not first_config.bypassed_checks
