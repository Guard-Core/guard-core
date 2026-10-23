import json
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from guard_core.models import SyncSecurityConfig, ThreatBanConfig
from guard_core.sync.core.checks.implementations.custom_validators import (
    CustomValidatorsCheck,
)
from guard_core.sync.core.checks.implementations.ip_security import IpSecurityCheck
from guard_core.sync.decorators import SecurityDecorator
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.handlers.ipban_handler import IPBanManager
from tests.test_sync.conftest import MockGuardResponse, SyncMockGuardRequest

BOT_IP = "203.0.113.7"
FORM = "application/x-www-form-urlencoded"
JSON = "application/json"


@pytest.fixture(autouse=True)
def fresh_ban_manager() -> Generator[IPBanManager, None, None]:
    IPBanManager._instance = None
    manager = IPBanManager()
    manager.redis_handler = None
    manager.config = SyncSecurityConfig(enable_redis=False)
    yield manager
    IPBanManager._instance = None


def _middleware(**overrides: Any) -> MagicMock:
    mw = MagicMock()
    mw.config = SyncSecurityConfig(enable_redis=False, **overrides)
    mw.logger = MagicMock()
    mw.event_bus.send_middleware_event = MagicMock()
    mw.create_error_response = MagicMock(return_value=MockGuardResponse("banned", 403))
    mw.route_resolver.should_bypass_check = MagicMock(return_value=False)
    mw.suspicious_request_counts = {}
    return mw


def _honeypot_route_config(config: SyncSecurityConfig) -> RouteConfig:
    func = Mock()
    func.__name__ = func.__qualname__ = "form_view"
    func.__module__ = "test_module"
    decorator = SecurityDecorator(config)
    decorated = decorator.honeypot_detection(["website"])(func)
    route_config = decorator.get_route_config(decorated._guard_route_id)
    assert route_config is not None
    return route_config


def _post(
    route_config: RouteConfig,
    content_type: str,
    body: bytes,
    method: str = "POST",
) -> SyncMockGuardRequest:
    request = SyncMockGuardRequest(
        method=method,
        headers={"content-type": content_type, "content-length": str(len(body))},
        body_content=body,
    )
    request.state.route_config = route_config
    request.state.client_ip = BOT_IP
    return request


def _check(
    mw: MagicMock, manager: IPBanManager, monkeypatch: pytest.MonkeyPatch
) -> tuple[CustomValidatorsCheck, MagicMock]:
    check = CustomValidatorsCheck(mw)
    check.ip_ban_manager = manager
    spy = MagicMock(wraps=manager._ban_ip_escalating)
    monkeypatch.setattr(manager, "_ban_ip_escalating", spy)
    return check, spy


TRAPPED = [
    pytest.param(FORM, b"name=bob&website=http%3A%2F%2Fspam", id="form"),
    pytest.param(
        JSON, json.dumps({"name": "bob", "website": "spam"}).encode(), id="json"
    ),
]


@pytest.mark.parametrize(("content_type", "body"), TRAPPED)
def test_filled_trap_bans_on_first_hit(
    fresh_ban_manager: IPBanManager,
    monkeypatch: pytest.MonkeyPatch,
    content_type: str,
    body: bytes,
) -> None:
    mw = _middleware(auto_ban_duration=900)
    route_config = _honeypot_route_config(mw.config)
    check, spy = _check(mw, fresh_ban_manager, monkeypatch)

    response = check.check(_post(route_config, content_type, body))

    assert response is not None
    assert response.status_code == 403
    assert BOT_IP not in mw.suspicious_request_counts
    spy.assert_called_once_with(
        BOT_IP, 900, "honeypot_triggered:honeypot", grouped=False
    )
    assert fresh_ban_manager.is_ip_banned(BOT_IP)


def test_banned_ip_is_blocked_by_ip_security_check(
    fresh_ban_manager: IPBanManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mw = _middleware()
    route_config = _honeypot_route_config(mw.config)
    check, _ = _check(mw, fresh_ban_manager, monkeypatch)
    check.check(_post(route_config, FORM, b"website=spam"))

    ip_check = IpSecurityCheck(mw)
    ip_check.ip_ban_manager = fresh_ban_manager
    follow_up = SyncMockGuardRequest()
    follow_up.state.client_ip = BOT_IP
    follow_up.state.route_config = None
    response = ip_check.check(follow_up)

    assert response is not None
    assert response.status_code == 403


def test_passive_mode_neither_counts_nor_bans(
    fresh_ban_manager: IPBanManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mw = _middleware(passive_mode=True)
    route_config = _honeypot_route_config(mw.config)
    check, spy = _check(mw, fresh_ban_manager, monkeypatch)

    response = check.check(_post(route_config, FORM, b"website=spam"))

    assert response is None
    assert mw.suspicious_request_counts == {}
    spy.assert_not_called()
    assert not fresh_ban_manager.is_ip_banned(BOT_IP)


def test_ip_banning_disabled_still_returns_403_without_ban(
    fresh_ban_manager: IPBanManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mw = _middleware(enable_ip_banning=False)
    route_config = _honeypot_route_config(mw.config)
    check, spy = _check(mw, fresh_ban_manager, monkeypatch)

    response = check.check(_post(route_config, FORM, b"website=spam"))

    assert response is not None
    assert response.status_code == 403
    spy.assert_not_called()
    assert not fresh_ban_manager.is_ip_banned(BOT_IP)


def test_threat_ban_config_overrides_threshold_and_duration(
    fresh_ban_manager: IPBanManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mw = _middleware(
        threat_ban_config={"honeypot": ThreatBanConfig(threshold=3, duration=42)}
    )
    route_config = _honeypot_route_config(mw.config)
    check, spy = _check(mw, fresh_ban_manager, monkeypatch)

    for _ in range(2):
        response = check.check(_post(route_config, FORM, b"website=spam"))
        assert response is not None
        assert response.status_code == 403
        spy.assert_not_called()
    check.check(_post(route_config, FORM, b"website=spam"))

    spy.assert_called_once_with(
        BOT_IP, 42, "honeypot_triggered:honeypot", grouped=False
    )
    assert fresh_ban_manager.is_ip_banned(BOT_IP)


@pytest.mark.parametrize(
    ("content_type", "body"),
    [
        pytest.param(FORM, b"name=bob&website=", id="form-empty"),
        pytest.param(FORM, b"name=bob", id="form-absent"),
        pytest.param(JSON, b'{"name": "bob", "website": ""}', id="json-empty"),
    ],
)
def test_unfilled_trap_passes_without_count(
    fresh_ban_manager: IPBanManager,
    monkeypatch: pytest.MonkeyPatch,
    content_type: str,
    body: bytes,
) -> None:
    mw = _middleware()
    route_config = _honeypot_route_config(mw.config)
    check, spy = _check(mw, fresh_ban_manager, monkeypatch)

    assert check.check(_post(route_config, content_type, body)) is None
    assert mw.suspicious_request_counts == {}
    spy.assert_not_called()


def test_get_request_without_a_trap_is_unaffected(
    fresh_ban_manager: IPBanManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mw = _middleware()
    route_config = _honeypot_route_config(mw.config)
    check, spy = _check(mw, fresh_ban_manager, monkeypatch)

    request = _post(route_config, FORM, b"website=", method="GET")

    assert check.check(request) is None
    spy.assert_not_called()


def test_non_honeypot_validator_rejection_does_not_ban(
    fresh_ban_manager: IPBanManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mw = _middleware()
    route_config = RouteConfig()
    route_config.custom_validators = [
        MagicMock(return_value=MockGuardResponse("no", 403))
    ]
    check, spy = _check(mw, fresh_ban_manager, monkeypatch)
    request = SyncMockGuardRequest()
    request.state.route_config = route_config
    request.state.client_ip = BOT_IP

    with patch(
        "guard_core.sync.core.checks.implementations.custom_validators.log_activity",
    ):
        response = check.check(request)

    assert response is not None
    assert response.status_code == 403
    assert mw.suspicious_request_counts == {}
    spy.assert_not_called()


def test_refused_ban_still_returns_403(
    fresh_ban_manager: IPBanManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mw = _middleware()
    route_config = _honeypot_route_config(mw.config)
    check, _ = _check(mw, fresh_ban_manager, monkeypatch)
    request = _post(route_config, FORM, b"website=spam")
    request.state.client_ip = "127.0.0.1"

    response = check.check(request)

    assert response is not None
    assert response.status_code == 403
    assert not fresh_ban_manager.is_ip_banned("127.0.0.1")


def test_missing_client_ip_skips_counting(
    fresh_ban_manager: IPBanManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mw = _middleware()
    route_config = _honeypot_route_config(mw.config)
    check, spy = _check(mw, fresh_ban_manager, monkeypatch)
    request = _post(route_config, FORM, b"website=spam")
    request.state.client_ip = None

    response = check.check(request)

    assert response is not None
    assert mw.suspicious_request_counts == {}
    spy.assert_not_called()


def test_a_honeypot_hit_from_a_whitelisted_ip_is_refused_but_never_banned(
    fresh_ban_manager: IPBanManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mw = _middleware(whitelist=[BOT_IP])
    route_config = _honeypot_route_config(mw.config)
    check, spy = _check(mw, fresh_ban_manager, monkeypatch)
    request = _post(route_config, FORM, b"website=spam")
    request.state.is_whitelisted = True

    response = check.check(request)

    assert response is not None
    assert response.status_code == 403
    spy.assert_not_called()
    assert mw.suspicious_request_counts == {}
    assert not fresh_ban_manager.is_ip_banned(BOT_IP)
