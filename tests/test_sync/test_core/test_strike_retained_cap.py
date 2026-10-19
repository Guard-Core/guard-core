import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.models import SecurityConfig, ThreatBanConfig
from guard_core.sync.core.checks import helpers
from guard_core.sync.core.checks._shared_strikes import record_shared_detection_strikes
from guard_core.sync.core.checks.helpers import (
    SUSPICIOUS_COUNT_WINDOW_SECONDS,
    _increment_suspicious_counts,
    _resolve_and_apply_threshold_ban,
)
from guard_core.sync.handlers.ipban_handler import IPBanManager
from guard_core.sync.handlers.ratelimit_handler import (
    _by_ip_autoban_counts,
    _feed_rate_limit_autoban,
)
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.test_sync.conftest import REDIS_URL

CLIENT_IP = "203.0.113.9"


class _RecordingBans:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int, str]] = []

    def _ban_ip_escalating(
        self, ip: str, duration: int, reason: str = "", *, grouped: bool = False
    ) -> bool:
        self.calls.append((ip, duration, reason))
        return duration


@pytest.fixture(autouse=True)
def _pinned_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        helpers, "time", SimpleNamespace(monotonic=lambda: 1000.0, time=lambda: 1000.0)
    )


def _middleware(config: SecurityConfig) -> Any:
    middleware = MagicMock()
    middleware.config = config
    middleware.suspicious_request_counts = {}
    return middleware


def _config(**fields: Any) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False, enable_ip_banning=True, enable_rate_limiting=False, **fields
    )


def _banned_after(
    middleware: Any, config: SecurityConfig, strikes: int, category: str = "xss"
) -> list[tuple[str, int, str]]:
    bans = _RecordingBans()
    for _ in range(strikes):
        _increment_suspicious_counts(middleware, CLIENT_IP, category)
    _resolve_and_apply_threshold_ban(
        middleware.suspicious_request_counts[CLIENT_IP],
        config,
        bans,
        CLIENT_IP,
        (category,),
        "penetration_attempt",
    )
    return bans.calls


def test_flat_threshold_above_the_floor_bans_on_that_strike() -> None:
    config = _config(auto_ban_threshold=10_001)
    middleware = _middleware(config)

    assert _banned_after(middleware, config, 10_000) == []
    assert _banned_after(middleware, config, 1) != []


def test_category_threshold_above_the_floor_bans_on_that_strike() -> None:
    config = _config(
        auto_ban_threshold=100_000,
        threat_ban_config={"xss": ThreatBanConfig(threshold=10_001, duration=60)},
    )
    middleware = _middleware(config)

    assert _banned_after(middleware, config, 10_000) == []
    assert _banned_after(middleware, config, 1) == [
        (CLIENT_IP, 60, "penetration_attempt:xss")
    ]


def test_a_dynamic_raise_after_the_floor_still_bans_at_the_new_threshold() -> None:
    config = _config(auto_ban_threshold=50_000)
    middleware = _middleware(config)
    assert _banned_after(middleware, config, 10_000) == []

    config.auto_ban_threshold = 20_000

    assert _banned_after(middleware, config, 9_999) == []
    assert _banned_after(middleware, config, 1) != []


def test_a_dynamic_lowering_trims_to_the_floor_and_bans_on_the_next_strike() -> None:
    config = _config(auto_ban_threshold=20_000)
    middleware = _middleware(config)
    assert _banned_after(middleware, config, 15_000) == []

    config.auto_ban_threshold = 5

    assert _banned_after(middleware, config, 1) != []
    assert middleware.suspicious_request_counts[CLIENT_IP]["xss"] == 10_000


def test_the_cap_follows_the_live_thresholds_per_revision() -> None:
    config = _config(auto_ban_threshold=10)
    assert helpers._retained_strike_cap(config) == 10_000
    config.auto_ban_threshold = 30_000
    assert helpers._retained_strike_cap(config) == 30_000
    assert helpers._retained_strike_cap(config) == 30_000
    other = _config(
        threat_ban_config={"sqli": ThreatBanConfig(threshold=40_000, duration=60)}
    )
    assert helpers._retained_strike_cap(other) == 40_000


def test_a_rate_limit_feed_threshold_above_the_floor_is_reachable() -> None:
    config = _config(
        enable_rate_limit_auto_ban=True,
        auto_ban_threshold=10_001,
        threat_ban_config={},
    )
    IPBanManager._instance = None
    manager = IPBanManager()
    manager.redis_handler = None
    manager.config = config
    bans = _RecordingBans()
    manager._ban_ip_escalating = bans._ban_ip_escalating  # type: ignore[method-assign]
    ip = "192.0.2.77"
    _by_ip_autoban_counts.clear()
    try:
        for _ in range(10_000):
            _feed_rate_limit_autoban(ip, config)
        assert bans.calls == []
        _feed_rate_limit_autoban(ip, config)
        assert bans.calls != []
    finally:
        IPBanManager._instance = None
        _by_ip_autoban_counts.clear()


def test_shared_redis_strikes_above_the_floor_count_every_strike() -> None:
    config = SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=f"test:wp9:cap:{uuid.uuid4().hex}:",
        enable_ip_banning=True,
        auto_ban_threshold=10_005,
    )
    redis = RedisManager(config)
    redis.initialize()
    middleware = _middleware(config)
    middleware.rate_limit_handler.redis_handler = redis
    cap = helpers._retained_strike_cap(config)
    try:
        shared = None
        for _ in range(10_005):
            shared = record_shared_detection_strikes(
                middleware,
                CLIENT_IP,
                ["xss"],
                SUSPICIOUS_COUNT_WINDOW_SECONDS,
                cap,
            )
        assert shared is not None
        assert shared.total == 10_005
        assert shared.counts == {"xss": 10_005}
    finally:
        redis.delete_pattern("*")
        redis.close()
