from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

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
    return RateLimitCheck(middleware)


def _request(path: str, route_id: str) -> Any:
    request = Mock()
    request.url_path = path
    request.state = Mock(spec=["guard_route_id"])
    request.state.guard_route_id = route_id
    return request


def _bucket(check: RateLimitCheck, kind: str, request: Any, route_config: Any) -> str:
    plan = (
        check._route_plan(request, route_config)
        if kind == "route"
        else check._geo_plan(request, "1.2.3.4", route_config)
    )
    assert plan is not None
    return plan.tier.bucket


@pytest.mark.parametrize("kind", ["route", "geo"])
async def test_route_and_geo_buckets_are_keyed_by_route_identity(
    check: RateLimitCheck, kind: str
) -> None:
    route_config = Mock(rate_limit=5, rate_limit_window=60)
    route_config.geo_rate_limits = {"US": (5, 60)}

    buckets = {
        _bucket(check, kind, _request(path, "app.users.get"), route_config)
        for path in SPELLINGS
    }

    assert buckets == {"app.users.get"}


async def test_two_routes_never_share_a_bucket(check: RateLimitCheck) -> None:
    route_config = Mock(rate_limit=5, rate_limit_window=60)

    buckets = [
        _bucket(check, "route", _request("/a", route_id), route_config)
        for route_id in ("app.a", "app.b")
    ]

    assert buckets == ["app.a", "app.b"]


@pytest.mark.parametrize("kind", ["route", "geo"])
async def test_a_request_without_a_route_id_keeps_the_path_bucket(
    check: RateLimitCheck, kind: str
) -> None:
    route_config = Mock(rate_limit=5, rate_limit_window=60)
    route_config.geo_rate_limits = {"US": (5, 60)}
    request = Mock()
    request.url_path = "/users/1"
    request.state = SimpleNamespace()

    assert _bucket(check, kind, request, route_config) == "/users/1"
