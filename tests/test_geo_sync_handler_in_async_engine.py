from unittest.mock import AsyncMock, MagicMock, patch

from guard_core.core.checks.factory import build_default_pipeline
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.decorators import SecurityDecorator
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest
from tests.test_core.conftest import build_middleware


class _SynchronousChinaHandler:
    def __init__(self, country: str = "CN") -> None:
        self.country = country
        self.is_initialized = False
        self.calls: list[str] = []

    def initialize(self) -> None:
        self.calls.append("initialize")
        self.is_initialized = True

    def initialize_redis(self, redis_handler: object) -> None:
        self.calls.append("initialize_redis")

    def initialize_agent(self, agent_handler: object) -> None:
        self.calls.append("initialize_agent")

    def get_country(self, ip: str) -> str | None:
        return self.country

    def refresh(self) -> None: ...

    def close(self) -> None: ...


async def test_a_synchronous_handler_blocks_a_country_in_the_async_engine() -> None:
    handler = _SynchronousChinaHandler()
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        geo_ip_handler=handler,
        blocked_countries=["CN"],
    )
    middleware = build_middleware(config, SecurityDecorator(config), handler)
    request = MockGuardRequest(path="/x", client_host="203.0.113.5")

    response = await build_default_pipeline(middleware).execute(request)

    assert response is not None and response.status_code == 403
    assert handler.calls == ["initialize"]


async def test_a_synchronous_handler_runs_every_initializer_step() -> None:
    handler = _SynchronousChinaHandler()
    config = SecurityConfig(enable_redis=False, geo_ip_handler=handler, lazy_init=False)
    initializer = HandlerInitializer(
        config, agent_handler=AsyncMock(), geo_ip_handler=handler
    )

    assert initializer.geo_ip_handler is handler
    await initializer._load_cloud_and_geo_without_redis()
    await initializer._initialize_cloud_and_geo_redis(MagicMock())
    with (
        patch("guard_core.handlers.ipban_handler.ip_ban_manager") as ipban,
        patch("guard_core.handlers.suspatterns_handler.sus_patterns_handler") as sus,
        patch(
            "guard_core.handlers.security_headers_handler.security_headers_manager"
        ) as headers,
    ):
        for manager in (ipban, sus, headers):
            manager.initialize_agent = AsyncMock()
        await initializer.initialize_agent_for_handlers()

    assert handler.calls == ["initialize", "initialize_redis", "initialize_agent"]


async def test_a_handler_without_the_optional_members_is_kept_and_initialized() -> None:
    config = SecurityConfig(enable_redis=False)
    no_members = MagicMock(spec=[])
    only_is_initialized = MagicMock(spec=["is_initialized"])

    for handler in (no_members, only_is_initialized):
        initializer = HandlerInitializer(config, geo_ip_handler=handler)
        assert initializer.geo_ip_handler is handler
        await initializer.initialize_agent_for_handlers()
    status = HandlerInitializer(
        config, geo_ip_handler=only_is_initialized
    ).get_initialization_status()
    assert status["geo_ip"] is not None


async def test_a_synchronous_handler_lets_an_allowed_country_through() -> None:
    handler = _SynchronousChinaHandler(country="US")
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        geo_ip_handler=handler,
        whitelist_countries=["US"],
    )
    middleware = build_middleware(config, SecurityDecorator(config), handler)
    request = MockGuardRequest(path="/x", client_host="203.0.113.5")

    response = await build_default_pipeline(middleware).execute(request)

    assert response is None
    assert handler.calls == ["initialize"]
