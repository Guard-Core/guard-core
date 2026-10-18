import uuid
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.sync.detection_result import DetectionResult
from guard_core.sync.handlers.ipban_handler import IPBanManager
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.test_sync.conftest import REDIS_URL

IDENTITY = "2001:db8:0:1::/64"
ADDRESSES = ["2001:db8:0:1::5", "2001:db8:0:1::6"]


@pytest.fixture(autouse=True)
def _reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


@pytest.fixture
def redis() -> Generator[RedisManager, None]:
    config = SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=f"test:wp9:grouped:{uuid.uuid4().hex}:",
    )
    manager = RedisManager(config)
    manager.initialize()
    try:
        yield manager
    finally:
        manager.delete_pattern("*")
        manager.close()


def _check(
    monkeypatch: pytest.MonkeyPatch, redis: RedisManager
) -> SuspiciousActivityCheck:
    config = SecurityConfig(
        enable_redis=True,
        redis_url=redis.config.redis_url,
        redis_prefix=redis.config.redis_prefix,
        enable_ip_banning=True,
        enable_penetration_detection=True,
        enable_rate_limiting=False,
        auto_ban_threshold=2,
        auto_ban_duration=600,
    )
    middleware = MagicMock()
    middleware.config = config
    middleware.suspicious_request_counts = {}
    middleware.rate_limit_handler.redis_handler = redis
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(
        return_value=MagicMock(status_code=403)
    )
    middleware.route_resolver.should_bypass_check = lambda *_: False
    check = SuspiciousActivityCheck(middleware)
    manager = IPBanManager()
    manager.config = config
    manager.redis_handler = redis
    check.ip_ban_manager = manager

    def detect(*_args: Any, **_kwargs: Any) -> DetectionResult:
        return DetectionResult(
            is_threat=True, trigger_info="probe", threat_categories=["xss"]
        )

    monkeypatch.setattr(
        "guard_core.sync.core.checks.implementations.suspicious_activity"
        ".get_cached_detection_result",
        detect,
    )
    return check


def _strike(check: SuspiciousActivityCheck, address: str) -> None:
    request = MagicMock()
    request.state.is_whitelisted = False
    request.state.client_ip = address
    request.state.route_config = None
    request.url_full = "https://test/x"
    check.check(request)


def test_a_detection_auto_ban_of_an_ipv6_client_bans_its_identity(
    monkeypatch: pytest.MonkeyPatch, redis: RedisManager
) -> None:
    check = _check(monkeypatch, redis)

    for address in ADDRESSES:
        _strike(check, address)

    assert redis.get_key("banned_identities", IDENTITY) is not None
    assert redis.get_key("banned_ips", ADDRESSES[1]) is None
    assert check.ip_ban_manager.is_ip_banned("2001:db8:0:1::99") is True


def test_an_ipv4_auto_ban_stays_a_per_address_ban(
    monkeypatch: pytest.MonkeyPatch, redis: RedisManager
) -> None:
    check = _check(monkeypatch, redis)

    for _ in range(2):
        _strike(check, "203.0.113.7")

    assert redis.get_key("banned_ips", "203.0.113.7") is not None


def test_an_operator_cidr_ban_is_not_an_identity_ban(
    monkeypatch: pytest.MonkeyPatch, redis: RedisManager
) -> None:
    check = _check(monkeypatch, redis)

    assert check.ip_ban_manager.ban_ip("2001:db8:7::/48", 600, "operator")

    assert redis.get_key("banned_identities", "2001:db8:7::/48") is None
