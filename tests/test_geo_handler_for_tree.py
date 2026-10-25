from collections.abc import Generator
from pathlib import Path
from types import SimpleNamespace

import pytest

from guard_core._geo_handler_for_tree import (
    build_geo_ip_handler_from_token,
    geo_ip_handler_for_tree,
    routes_need_geo_ip_handler,
)
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.handlers.ipinfo_handler import IPInfoManager as AsyncIPInfoManager
from guard_core.models import SecurityConfig
from guard_core.sync.core.initialization.handler_initializer import (
    HandlerInitializer as SyncHandlerInitializer,
)
from guard_core.sync.handlers.ipinfo_handler import IPInfoManager as SyncIPInfoManager
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


@pytest.fixture(autouse=True)
def _reset_singletons() -> Generator[None, None, None]:
    AsyncIPInfoManager._instance = None
    SyncIPInfoManager._instance = None
    yield
    AsyncIPInfoManager._instance = None
    SyncIPInfoManager._instance = None


def _config(
    tmp_path: Path, blocked_countries: list[str] | None = None
) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        ipinfo_token="tok",
        ipinfo_db_path=tmp_path / "geo.mmdb",
        blocked_countries=blocked_countries,
    )


class _AsyncHandler:
    is_initialized = True

    async def initialize(self) -> None: ...

    async def initialize_redis(self, redis_handler: object) -> None: ...

    async def initialize_agent(self, agent_handler: object) -> None: ...

    def get_country(self, ip: str) -> str | None:
        return None

    async def refresh(self) -> None: ...

    def close(self) -> None: ...


class _SyncHandler:
    is_initialized = True

    def initialize(self) -> None: ...

    def initialize_redis(self, redis_handler: object) -> None: ...

    def initialize_agent(self, agent_handler: object) -> None: ...

    def get_country(self, ip: str) -> str | None:
        return None

    def refresh(self) -> None: ...

    def close(self) -> None: ...


def test_sync_engine_swaps_the_handler_the_config_built_from_the_token(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path, blocked_countries=["CN"])
    assert isinstance(config.geo_ip_handler, AsyncIPInfoManager)

    resolved = geo_ip_handler_for_tree(config, config.geo_ip_handler, tree_awaits=False)

    assert isinstance(resolved, SyncIPInfoManager)
    assert resolved.token == "tok"
    assert resolved.db_path == tmp_path / "geo.mmdb"


def test_async_engine_keeps_the_handler_the_config_built(tmp_path: Path) -> None:
    config = _config(tmp_path, blocked_countries=["CN"])

    resolved = geo_ip_handler_for_tree(config, config.geo_ip_handler, tree_awaits=True)

    assert resolved is config.geo_ip_handler


def test_sync_engine_refuses_a_user_supplied_async_handler(tmp_path: Path) -> None:
    config = SecurityConfig(enable_redis=False, geo_ip_handler=_AsyncHandler())

    with pytest.raises(ValueError, match="is async") as raised:
        geo_ip_handler_for_tree(config, config.geo_ip_handler, tree_awaits=False)

    assert "initialize, initialize_redis, initialize_agent, refresh" in str(
        raised.value
    )
    assert "guard_core.sync.handlers.ipinfo_handler.IPInfoManager" in str(raised.value)


def test_sync_engine_refuses_an_async_ipinfo_manager_the_config_did_not_build(
    tmp_path: Path,
) -> None:
    config = SecurityConfig(
        enable_redis=False,
        geo_ip_handler=AsyncIPInfoManager("other", tmp_path / "geo.mmdb"),
    )

    with pytest.raises(ValueError, match="is async"):
        geo_ip_handler_for_tree(config, config.geo_ip_handler, tree_awaits=False)


def test_sync_engine_keeps_a_user_supplied_sync_handler(tmp_path: Path) -> None:
    handler = _SyncHandler()
    config = SecurityConfig(enable_redis=False, geo_ip_handler=handler)

    assert geo_ip_handler_for_tree(config, handler, tree_awaits=False) is handler


def test_sync_engine_keeps_the_sync_ipinfo_manager_documented_for_sync_adapters(
    tmp_path: Path,
) -> None:
    handler = SyncIPInfoManager("tok", tmp_path / "geo.mmdb")
    config = SecurityConfig(enable_redis=False, geo_ip_handler=handler)

    assert geo_ip_handler_for_tree(config, handler, tree_awaits=False) is handler


def test_no_handler_stays_no_handler() -> None:
    config = SecurityConfig(enable_redis=False)

    assert geo_ip_handler_for_tree(config, None, tree_awaits=False) is None
    assert geo_ip_handler_for_tree(config, None, tree_awaits=True) is None


def test_the_handler_built_from_the_token_matches_the_tree(tmp_path: Path) -> None:
    config = _config(tmp_path)

    assert isinstance(
        build_geo_ip_handler_from_token(config, tree_awaits=False), SyncIPInfoManager
    )
    assert isinstance(
        build_geo_ip_handler_from_token(config, tree_awaits=True), AsyncIPInfoManager
    )


def test_only_a_country_rule_on_a_route_needs_a_handler() -> None:
    def route(
        blocked_countries: list[str] | None = None,
        whitelist_countries: list[str] | None = None,
        geo_rate_limits: dict[str, tuple[int, int]] | None = None,
    ) -> SimpleNamespace:
        return SimpleNamespace(
            blocked_countries=blocked_countries,
            whitelist_countries=whitelist_countries,
            geo_rate_limits=geo_rate_limits or {},
        )

    assert not routes_need_geo_ip_handler([route()])
    assert routes_need_geo_ip_handler([route(), route(blocked_countries=["CN"])])
    assert routes_need_geo_ip_handler([route(whitelist_countries=["US"])])
    assert routes_need_geo_ip_handler([route(geo_rate_limits={"CN": (1, 60)})])


def test_sync_handler_initializer_refuses_an_async_handler_at_startup() -> None:
    config = SecurityConfig[SyncGuardRequest](enable_redis=False)

    with pytest.raises(ValueError, match="is async"):
        SyncHandlerInitializer(config, geo_ip_handler=_AsyncHandler())


def test_async_handler_initializer_accepts_an_async_handler() -> None:
    config = SecurityConfig(enable_redis=False)
    handler = _AsyncHandler()

    assert HandlerInitializer(config, geo_ip_handler=handler).geo_ip_handler is handler


def test_sync_handler_initializer_runs_with_the_sync_handler_for_the_token(
    tmp_path: Path,
) -> None:
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        ipinfo_token="tok",
        ipinfo_db_path=tmp_path / "geo.mmdb",
        blocked_countries=["CN"],
    )

    initializer = SyncHandlerInitializer(config, geo_ip_handler=config.geo_ip_handler)

    assert isinstance(initializer.geo_ip_handler, SyncIPInfoManager)
