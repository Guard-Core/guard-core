from collections.abc import Generator
from typing import Any

import pytest

from guard_core.core.checks.factory import build_default_pipeline
from guard_core.decorators import SecurityDecorator
from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest
from tests.test_core.conftest import build_middleware

CLIENT = "203.0.113.40"
BAD_AGENT = {"User-Agent": "badbot/1.0"}


@pytest.fixture(autouse=True)
def _fresh_ban_store() -> Generator[None, None, None]:
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.banned_networks.clear()
    ip_ban_manager.redis_handler = None
    yield
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.banned_networks.clear()


def _config(**settings: object) -> SecurityConfig:
    defaults: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
        "whitelist": [CLIENT],
        "blocked_user_agents": ["badbot"],
    }
    return SecurityConfig(**{**defaults, **settings})


async def _run(config: SecurityConfig) -> tuple[int | None, object]:
    middleware = build_middleware(config, SecurityDecorator(config))
    request = MockGuardRequest(path="/x", client_host=CLIENT, headers=BAD_AGENT)
    response = await build_default_pipeline(middleware).execute(request)
    return (None if response is None else response.status_code), (
        request.state.is_whitelisted
    )


def test_the_flag_defaults_to_on() -> None:
    config = _config()

    assert config.whitelist_access_only is True
    assert "whitelist_access_only" not in config.model_fields_set


async def test_an_unset_flag_checks_a_whitelisted_ip_like_any_other_client() -> None:
    assert await _run(_config()) == (403, False)


async def test_the_old_value_restores_the_whitelist_skips() -> None:
    assert await _run(_config(whitelist_access_only=False)) == (None, True)
