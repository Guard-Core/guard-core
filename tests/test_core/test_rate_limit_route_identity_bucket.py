from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest

from guard_core.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.models import SecurityConfig

SPELLINGS = ["/users/1", "/users/2", "/users/1/", "//users/1", "/USERS/1"]


@pytest.fixture
def check() -> RateLimitCheck:
    config = SecurityConfig(enable_redis=False)
    geo_handler = Mock()
    geo_handler.get_country.return_value = "US"
    middleware = Mock()
    middleware.config = config
    middleware.geo_ip_handler = geo_handler
    middleware.rate_limit_handler.check_rate_limit = AsyncMock(return_value=None)
    return RateLimitCheck(middleware)


def _request(path: str, route_id: str) -> Any:
    request = Mock()
    request.url_path = path
    request.state = Mock(spec=["guard_route_id"])
    request.state.guard_route_id = route_id
    return request


def _bucket_paths(check: RateLimitCheck) -> list[str]:
    handler = check.middleware.rate_limit_handler.check_rate_limit
    return [call.kwargs["endpoint_path"] for call in handler.call_args_list]


@pytest.mark.parametrize("kind", ["route", "geo"])
async def test_route_and_geo_buckets_are_keyed_by_route_identity(
    check: RateLimitCheck, kind: str
) -> None:
    route_config = Mock(rate_limit=5, rate_limit_window=60)
    route_config.geo_rate_limits = {"US": (5, 60)}
    method = (
        check._check_route_rate_limit
        if kind == "route"
        else check._check_geo_rate_limit
    )
    for path in SPELLINGS:
        await method(_request(path, "app.users.get"), "1.2.3.4", route_config)

    assert set(_bucket_paths(check)) == {"app.users.get"}


async def test_two_routes_never_share_a_bucket(check: RateLimitCheck) -> None:
    route_config = Mock(rate_limit=5, rate_limit_window=60)
    await check._check_route_rate_limit(
        _request("/a", "app.a"), "1.2.3.4", route_config
    )
    await check._check_route_rate_limit(
        _request("/a", "app.b"), "1.2.3.4", route_config
    )

    assert _bucket_paths(check) == ["app.a", "app.b"]


@pytest.mark.parametrize("kind", ["route", "geo"])
async def test_a_request_without_a_route_id_keeps_the_path_bucket(
    check: RateLimitCheck, kind: str
) -> None:
    route_config = Mock(rate_limit=5, rate_limit_window=60)
    route_config.geo_rate_limits = {"US": (5, 60)}
    method = (
        check._check_route_rate_limit
        if kind == "route"
        else check._check_geo_rate_limit
    )
    request = Mock()
    request.url_path = "/users/1"
    request.state = SimpleNamespace()

    await method(request, "1.2.3.4", route_config)

    assert _bucket_paths(check) == ["/users/1"]
