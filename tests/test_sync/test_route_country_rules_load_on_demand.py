from collections.abc import Generator
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.helpers import check_route_ip_access
from guard_core.sync.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.decorators import SecurityDecorator
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.handlers.ipinfo_handler import IPInfoManager
from tests.geo_fixture import CLIENT_IP, country_database_bytes


@pytest.fixture(autouse=True)
def _reset_singleton() -> Generator[None, None, None]:
    IPInfoManager._instance = None
    yield
    IPInfoManager._instance = None


def _default_lazy_init_engine(
    tmp_path: Path, rule: str, *args: object
) -> tuple[HandlerInitializer, RouteConfig]:
    db_path = tmp_path / "geo.mmdb"
    db_path.write_bytes(country_database_bytes("CN"))
    config = SyncSecurityConfig(
        enable_redis=False, ipinfo_token="tok", ipinfo_db_path=db_path
    )
    assert config.lazy_init is True
    decorator = SecurityDecorator(config)
    getattr(decorator, rule)(*args)(lambda: None)
    initializer = HandlerInitializer(config, guard_decorator=decorator)
    initializer.initialize_redis_handlers()
    assert initializer.geo_ip_handler is not None
    assert not initializer.geo_ip_handler.is_initialized
    [route_config] = decorator._route_configs.values()
    return initializer, route_config


def _middleware(initializer: HandlerInitializer) -> SimpleNamespace:
    return SimpleNamespace(geo_ip_handler=initializer.geo_ip_handler)


def test_route_only_block_countries_blocks_a_mapped_ip(tmp_path: Path) -> None:
    initializer, route_config = _default_lazy_init_engine(
        tmp_path, "block_countries", ["CN"]
    )

    assert (
        check_route_ip_access(CLIENT_IP, route_config, _middleware(initializer))
        is False
    )


def test_route_only_allow_countries_admits_a_mapped_ip(tmp_path: Path) -> None:
    initializer, route_config = _default_lazy_init_engine(
        tmp_path, "allow_countries", ["CN"]
    )

    assert (
        check_route_ip_access(CLIENT_IP, route_config, _middleware(initializer)) is True
    )


def test_route_geo_rate_limit_applies_its_country_limit(tmp_path: Path) -> None:
    initializer, route_config = _default_lazy_init_engine(
        tmp_path, "geo_rate_limit", {"CN": (3, 60)}
    )
    middleware = Mock()
    middleware.config = initializer.config
    middleware.geo_ip_handler = initializer.geo_ip_handler
    middleware.route_resolver.should_bypass_check = Mock(return_value=False)
    middleware.rate_limit_handler.check_rate_limit_tiers = MagicMock(return_value=None)
    request = Mock()
    request.state.client_ip = CLIENT_IP
    request.state.route_config = route_config
    request.state.is_whitelisted = False
    request.url_path = "/x"
    request.method = "GET"
    request.headers = {}

    RateLimitCheck(middleware).check(request)

    tiers = middleware.rate_limit_handler.check_rate_limit_tiers.call_args[0][3]
    assert [(t.kind, t.limit, t.window) for t in tiers if t.kind == "geo"] == [
        ("geo", 3, 60)
    ]


def test_a_route_without_a_country_rule_never_loads_the_database(
    tmp_path: Path,
) -> None:
    initializer, _ = _default_lazy_init_engine(tmp_path, "block_countries", ["CN"])
    plain_route = RouteConfig()

    check_route_ip_access(CLIENT_IP, plain_route, _middleware(initializer))

    handler = initializer.geo_ip_handler
    assert isinstance(handler, IPInfoManager)
    assert handler.is_initialized is False


def test_the_database_loads_once_and_a_missing_handler_is_left_alone(
    tmp_path: Path,
) -> None:
    initializer, route_config = _default_lazy_init_engine(
        tmp_path, "block_countries", ["CN"]
    )
    middleware = _middleware(initializer)

    for _ in range(2):
        assert check_route_ip_access(CLIENT_IP, route_config, middleware) is False
    handler = initializer.geo_ip_handler
    assert isinstance(handler, IPInfoManager)
    assert handler.is_initialized is True

    middleware.geo_ip_handler = None
    assert check_route_ip_access(CLIENT_IP, route_config, middleware) is None
