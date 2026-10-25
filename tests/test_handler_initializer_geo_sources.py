from collections.abc import Generator
from pathlib import Path

import pytest

from guard_core._utils.access_control import check_ip_country
from guard_core.core.checks.helpers import check_country_access
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.decorators import SecurityDecorator
from guard_core.handlers.ipinfo_handler import IPInfoManager
from guard_core.models import SecurityConfig
from tests.geo_fixture import CLIENT_IP, country_database_bytes


@pytest.fixture(autouse=True)
def _reset_singleton() -> Generator[None, None, None]:
    IPInfoManager._instance = None
    yield
    IPInfoManager._instance = None


def _config(tmp_path: Path, **rules: object) -> SecurityConfig:
    db_path = tmp_path / "geo.mmdb"
    db_path.write_bytes(country_database_bytes("CN"))
    return SecurityConfig(
        enable_redis=False, ipinfo_token="tok", ipinfo_db_path=db_path, **rules
    )


async def test_global_country_rule_from_the_token_blocks_on_the_engine_handler(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path, blocked_countries=["CN"])
    initializer = HandlerInitializer(config, geo_ip_handler=config.geo_ip_handler)

    assert isinstance(initializer.geo_ip_handler, IPInfoManager)
    assert await check_ip_country(CLIENT_IP, config, initializer.geo_ip_handler)


async def test_route_only_country_rule_gets_a_handler_built_from_the_token(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path, lazy_init=False)
    decorator = SecurityDecorator(config)

    @decorator.block_countries(["CN"])
    def view() -> None: ...

    initializer = HandlerInitializer(config, guard_decorator=decorator)
    await initializer.initialize_redis_handlers()

    assert isinstance(initializer.geo_ip_handler, IPInfoManager)
    assert initializer.geo_ip_handler.token == "tok"
    [route_config] = decorator._route_configs.values()
    assert check_country_access(
        CLIENT_IP, route_config, initializer.geo_ip_handler
    ) is (False)


async def test_no_handler_is_built_when_no_route_or_global_rule_uses_geo(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    decorator = SecurityDecorator(config)

    @decorator.require_https()
    def view() -> None: ...

    initializer = HandlerInitializer(config, guard_decorator=decorator)
    await initializer.initialize_redis_handlers()

    assert initializer.geo_ip_handler is None


async def test_route_rule_without_a_token_keeps_no_handler(tmp_path: Path) -> None:
    config = SecurityConfig(enable_redis=False, fail_on_misconfiguration=False)
    decorator = SecurityDecorator(config)

    @decorator.block_countries(["CN"])
    def view() -> None: ...

    initializer = HandlerInitializer(config, guard_decorator=decorator)
    await initializer.initialize_redis_handlers()

    assert initializer.geo_ip_handler is None
