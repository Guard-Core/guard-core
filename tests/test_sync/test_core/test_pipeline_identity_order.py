from typing import Any
from unittest.mock import MagicMock

from guard_core.models import SecurityConfig
from guard_core.sync.core.checks import build_default_pipeline
from guard_core.sync.handlers import ipban_handler
from tests.test_sync.conftest import SyncMockGuardRequest
from tests.test_sync.test_core.conftest import (
    build_route_pipeline,
    fully_enabled_config,
    fully_enabled_route_config,
    middleware_for,
    send_request,
)

BOT_IP = "203.0.113.7"
GOOD_HEADERS = {"X-API-Key": "secret", "referer": "https://example.com/page"}


def _config(**overrides: Any) -> SecurityConfig:
    settings: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
        "auto_ban_threshold": 2,
    }
    settings.update(overrides)
    return SecurityConfig(**settings)


def test_ip_security_and_rate_limit_run_before_the_identity_checks() -> None:
    middleware = middleware_for(
        fully_enabled_config(), route_configs=(fully_enabled_route_config(),)
    )

    names = build_default_pipeline(middleware).get_check_names()

    assert names[:9] == [
        "route_config",
        "emergency_mode",
        "https_enforcement",
        "request_logging",
        "request_size_content",
        "cloud_ip_refresh",
        "ip_security",
        "cloud_provider",
        "user_agent",
    ]
    assert names[9:] == [
        "cors_preflight",
        "rate_limit",
        "required_headers",
        "authentication",
        "referrer",
        "custom_validators",
        "time_window",
        "suspicious_activity",
        "custom_request",
    ]


def test_banned_ip_never_reaches_the_verifier() -> None:
    verifier = MagicMock(return_value=True)
    pipeline, _, route_id = build_route_pipeline(
        _config(), lambda d: d.api_key_auth(verifier=verifier)
    )
    ipban_handler.ip_ban_manager.ban_ip(BOT_IP, 600, "test")

    response = send_request(
        pipeline, route_id, ip=BOT_IP, headers={"X-API-Key": "secret"}
    )

    assert response is not None
    assert response.status_code == 403
    verifier.assert_not_called()


def test_banned_ip_never_reaches_a_custom_validator_or_header_check() -> None:
    validator = MagicMock(return_value=None)
    pipeline, _, route_id = build_route_pipeline(
        _config(),
        lambda d: d.custom_validation(validator),
        lambda d: d.require_headers({"X-Trace": "required"}),
    )
    ipban_handler.ip_ban_manager.ban_ip(BOT_IP, 600, "test")

    response = send_request(pipeline, route_id, ip=BOT_IP)

    assert response is not None
    assert response.status_code == 403
    validator.assert_not_called()


def test_blacklisted_ip_gets_403_not_401_and_skips_the_verifier() -> None:
    verifier = MagicMock(return_value=True)
    pipeline, _, route_id = build_route_pipeline(
        _config(blacklist=[BOT_IP]), lambda d: d.api_key_auth(verifier=verifier)
    )

    response = send_request(pipeline, route_id, ip=BOT_IP)

    assert response is not None
    assert response.status_code == 403
    verifier.assert_not_called()


def test_rate_limited_client_stops_reaching_the_verifier() -> None:
    verifier = MagicMock(return_value=False)
    pipeline, _, route_id = build_route_pipeline(
        _config(enable_rate_limiting=True, rate_limit=1, rate_limit_window=60),
        lambda d: d.api_key_auth(verifier=verifier),
    )

    statuses = []
    for _ in range(4):
        response = send_request(pipeline, route_id, ip=BOT_IP, headers=GOOD_HEADERS)
        assert response is not None
        statuses.append(response.status_code)

    assert statuses == [401, 429, 429, 429]
    assert verifier.call_count == 1


def test_authenticated_request_still_carries_the_principal() -> None:
    verifier = MagicMock(return_value={"user": "u1"})
    config = _config()
    pipeline, _, route_id = build_route_pipeline(
        config,
        lambda d: d.api_key_auth(verifier=verifier),
        lambda d: d.require_referrer(["example.com"]),
    )
    request = SyncMockGuardRequest(
        path="/x", headers=GOOD_HEADERS, client_host=BOT_IP, scheme="https"
    )
    request.state.guard_route_id = route_id

    assert pipeline.execute(request) is None
    assert request.state.auth_principal == {"user": "u1"}


def test_whitelisted_client_is_not_counted_for_identity_failures() -> None:
    config = _config(
        whitelist=[BOT_IP], ban_on_hostile_signals=True, whitelist_access_only=False
    )
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.require_referrer(["example.com"])
    )

    for _ in range(3):
        send_request(pipeline, route_id, ip=BOT_IP)

    assert middleware.suspicious_request_counts == {}
    assert not ipban_handler.ip_ban_manager.is_ip_banned(BOT_IP)
