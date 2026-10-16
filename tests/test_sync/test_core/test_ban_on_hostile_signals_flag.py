import warnings
from collections.abc import Callable
from typing import Any
from unittest.mock import patch

import pytest

from guard_core import _security_config_field_validators as field_validators
from guard_core.models import SecurityConfig
from guard_core.sync.decorators import SecurityDecorator
from guard_core.sync.handlers import ipban_handler
from tests.test_sync.test_core.conftest import (
    build_route_pipeline,
    fixed_country_geo_ip,
    send_request,
)

DecoratorFactory = Callable[[SecurityDecorator], Any]

BOT_IP = "203.0.113.7"
SQLI_PATH = "/x?q=1%20UNION%20SELECT%20password%20FROM%20users--"


def _config(**overrides: Any) -> SecurityConfig:
    settings: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
        "auto_ban_threshold": 2,
        "geo_ip_handler": fixed_country_geo_ip("CN"),
        "ban_on_hostile_signals": False,
    }
    settings.update(overrides)
    return SecurityConfig(**settings)


FLAGGED_DENIALS = [
    pytest.param(
        {},
        lambda d: d.api_key_auth(verifier=lambda r, k: False),
        {"headers": {"X-API-Key": "wrong"}},
        id="auth-failure",
    ),
    pytest.param(
        {},
        lambda d: d.require_headers({"X-Trace": "required"}),
        {},
        id="required-header",
    ),
    pytest.param({}, lambda d: d.require_referrer(["example.com"]), {}, id="referrer"),
    pytest.param(
        {}, lambda d: d.require_ip(blacklist=[BOT_IP]), {}, id="route-ip-blacklist"
    ),
    pytest.param(
        {}, lambda d: d.block_countries(["CN"]), {}, id="route-blocked-country"
    ),
    pytest.param(
        {},
        lambda d: d.block_user_agents(["badbot"]),
        {"headers": {"User-Agent": "badbot/1.0"}},
        id="route-user-agent",
    ),
    pytest.param(
        {"blacklist": [BOT_IP]},
        lambda d: d.max_request_size(10**6),
        {},
        id="global-blacklist",
    ),
    pytest.param(
        {"blocked_user_agents": ["badbot"]},
        lambda d: d.max_request_size(10**6),
        {"headers": {"User-Agent": "badbot/1.0"}},
        id="global-user-agent",
    ),
]


@pytest.mark.parametrize(("settings", "factory", "request_kwargs"), FLAGGED_DENIALS)
def test_flag_off_never_counts_without_a_penetration_match(
    settings: dict[str, Any], factory: DecoratorFactory, request_kwargs: dict[str, Any]
) -> None:
    config = _config(**settings)
    pipeline, middleware, route_id = build_route_pipeline(
        config, factory, geo_ip_handler=config.geo_ip_handler
    )

    for _ in range(4):
        response = send_request(pipeline, route_id, ip=BOT_IP, **request_kwargs)
        assert response is not None
        assert response.status_code != 200

    assert middleware.suspicious_request_counts == {}
    assert not ipban_handler.ip_ban_manager.is_ip_banned(BOT_IP)


@pytest.mark.parametrize(("settings", "factory", "request_kwargs"), FLAGGED_DENIALS)
def test_flag_on_counts_and_bans(
    settings: dict[str, Any], factory: DecoratorFactory, request_kwargs: dict[str, Any]
) -> None:
    config = _config(ban_on_hostile_signals=True, **settings)
    pipeline, _, route_id = build_route_pipeline(
        config, factory, geo_ip_handler=config.geo_ip_handler
    )

    for _ in range(2):
        send_request(pipeline, route_id, ip=BOT_IP, **request_kwargs)

    assert ipban_handler.ip_ban_manager.is_ip_banned(BOT_IP)


def test_flag_off_keeps_the_conditional_penetration_escalation() -> None:
    config = _config(enable_penetration_detection=True, auto_ban_threshold=5)
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.require_ip(blacklist=[BOT_IP])
    )

    send_request(pipeline, route_id, ip=BOT_IP, path=SQLI_PATH)

    assert set(middleware.suspicious_request_counts[BOT_IP]) == {"sqli"}


def test_flag_off_keeps_the_conditional_global_escalation() -> None:
    config = _config(
        enable_penetration_detection=True, auto_ban_threshold=5, blacklist=[BOT_IP]
    )
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.max_request_size(10**6)
    )

    send_request(pipeline, route_id, ip=BOT_IP, path=SQLI_PATH)

    assert set(middleware.suspicious_request_counts[BOT_IP]) == {"sqli"}


def test_flag_off_leaves_honeypot_banning_on() -> None:
    config = _config()
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.honeypot_detection(["hp"])
    )

    response = send_request(
        pipeline,
        route_id,
        ip=BOT_IP,
        method="POST",
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "content-length": "6",
        },
        body=b"hp=bot",
    )

    assert response is not None
    assert response.status_code == 403
    assert ipban_handler.ip_ban_manager.is_ip_banned(BOT_IP)


def test_flag_off_cloud_denial_keeps_global_escalation_only() -> None:
    config = _config(
        block_cloud_providers={"AWS"},
        enable_penetration_detection=True,
        auto_ban_threshold=5,
    )
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.max_request_size(10**6)
    )
    with patch(
        "guard_core.sync.handlers.cloud_handler.cloud_handler.is_cloud_ip",
        return_value=True,
    ):
        response = send_request(pipeline, route_id, ip=BOT_IP, path=SQLI_PATH)

    assert response is not None
    assert response.status_code == 403
    assert set(middleware.suspicious_request_counts[BOT_IP]) == {"sqli"}


def test_flag_defaults_to_off() -> None:
    assert SecurityConfig(ban_on_hostile_signals=False).ban_on_hostile_signals is False
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        assert SecurityConfig().ban_on_hostile_signals is False


@pytest.fixture
def armed_deprecation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(field_validators, "_hostile_signal_ban_default_warned", False)


@pytest.mark.usefixtures("armed_deprecation")
def test_unset_flag_warns_once_with_a_deprecation_warning_and_a_log_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level("WARNING", logger="guard_core"):
        with pytest.warns(DeprecationWarning, match="guard-core 5.0.0 turns it on"):
            SecurityConfig()
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            SecurityConfig()

    messages = [
        record.getMessage()
        for record in caplog.records
        if "ban_on_hostile_signals" in record.getMessage()
    ]
    assert len(messages) == 1
    assert "ban_on_hostile_signals=True" in messages[0]


@pytest.mark.usefixtures("armed_deprecation")
@pytest.mark.parametrize("value", [True, False])
def test_explicit_flag_never_warns(value: bool) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        SecurityConfig(ban_on_hostile_signals=value)

    assert field_validators._hostile_signal_ban_default_warned is False
