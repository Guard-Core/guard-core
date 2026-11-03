from collections.abc import Generator
from typing import Any

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.factory import build_default_pipeline
from guard_core.sync.decorators import SecurityDecorator
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from tests.test_sync.conftest import SyncMockGuardRequest
from tests.test_sync.test_core.conftest import build_middleware

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


def _config(**settings: object) -> SyncSecurityConfig:
    defaults: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
        "whitelist": [CLIENT],
        "blocked_user_agents": ["badbot"],
    }
    return SyncSecurityConfig(**{**defaults, **settings})


def _run(config: SyncSecurityConfig) -> tuple[int | None, object]:
    middleware = build_middleware(config, SecurityDecorator(config))
    request = SyncMockGuardRequest(path="/x", client_host=CLIENT, headers=BAD_AGENT)
    response = build_default_pipeline(middleware).execute(request)
    return (None if response is None else response.status_code), (
        request.state.is_whitelisted
    )


def test_the_flag_defaults_to_on() -> None:
    config = _config()

    assert config.whitelist_access_only is True
    assert "whitelist_access_only" not in config.model_fields_set


def test_an_unset_flag_checks_a_whitelisted_ip_like_any_other_client() -> None:
    assert _run(_config()) == (403, False)


def test_the_old_value_restores_the_whitelist_skips() -> None:
    assert _run(_config(whitelist_access_only=False)) == (None, True)
