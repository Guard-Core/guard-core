from collections.abc import Callable
from typing import Any

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.decorators import SecurityDecorator
from guard_core.sync.handlers import ipban_handler
from tests.test_sync.test_core.conftest import build_route_pipeline, send_request

DecoratorFactory = Callable[[SecurityDecorator], Any]

BOT_IP = "203.0.113.7"

UNSET_DENIALS = [
    pytest.param(
        lambda d: d.api_key_auth(verifier=lambda r, k: False),
        {"headers": {"X-API-Key": "wrong"}},
        id="auth-failure",
    ),
    pytest.param(
        lambda d: d.require_headers({"X-Trace": "required"}), {}, id="required-header"
    ),
    pytest.param(
        lambda d: d.require_ip(blacklist=[BOT_IP]), {}, id="route-ip-blacklist"
    ),
]


def _config(**overrides: object) -> SyncSecurityConfig:
    settings: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
        "auto_ban_threshold": 2,
    }
    settings.update(overrides)
    return SyncSecurityConfig(**settings)


def test_the_flag_defaults_to_on() -> None:
    assert SyncSecurityConfig(enable_redis=False).ban_on_hostile_signals is True


@pytest.mark.parametrize(("factory", "request_kwargs"), UNSET_DENIALS)
def test_an_unset_flag_bans_repeated_hostile_signals(
    factory: DecoratorFactory, request_kwargs: dict[str, Any]
) -> None:
    config = _config()
    assert "ban_on_hostile_signals" not in config.model_fields_set
    pipeline, _, route_id = build_route_pipeline(config, factory)

    for _ in range(2):
        send_request(pipeline, route_id, ip=BOT_IP, **request_kwargs)

    assert ipban_handler.ip_ban_manager.is_ip_banned(BOT_IP)


@pytest.mark.parametrize(("factory", "request_kwargs"), UNSET_DENIALS)
def test_the_old_value_restores_the_old_behavior(
    factory: DecoratorFactory, request_kwargs: dict[str, Any]
) -> None:
    config = _config(ban_on_hostile_signals=False)
    pipeline, middleware, route_id = build_route_pipeline(config, factory)

    for _ in range(4):
        send_request(pipeline, route_id, ip=BOT_IP, **request_kwargs)

    assert middleware.suspicious_request_counts == {}
    assert not ipban_handler.ip_ban_manager.is_ip_banned(BOT_IP)
