import logging
import time
from collections.abc import Generator

import pytest

from guard_core.sync.handlers.ipban_handler import IPBanManager


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


def test_ban_short_duration_succeeds_when_redis_unavailable(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.banned_ips.clear()

    caplog.set_level(logging.WARNING, logger="guard_core.sync.handlers.ipban")
    manager.ban_ip("8.8.8.5", duration=300, reason="test")

    assert "8.8.8.5" in manager.banned_ips
    expiry = manager.banned_ips["8.8.8.5"]
    assert expiry == pytest.approx(time.time() + 300, abs=2)
    assert not [r for r in caplog.records if r.levelno == logging.WARNING]


def test_ban_at_cap_succeeds_when_redis_unavailable(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.banned_ips.clear()

    caplog.set_level(logging.WARNING, logger="guard_core.sync.handlers.ipban")
    manager.ban_ip(
        "8.8.8.6", duration=manager.LOCAL_CACHE_TTL_CAP_SECONDS, reason="test"
    )

    assert "8.8.8.6" in manager.banned_ips
    assert not [r for r in caplog.records if r.levelno == logging.WARNING]


def test_ban_longer_than_the_old_cap_keeps_its_duration_without_redis(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.banned_ips.clear()

    caplog.set_level(logging.WARNING, logger="guard_core.sync.handlers.ipban")
    manager.ban_ip(
        "8.8.8.7",
        duration=manager.LOCAL_CACHE_TTL_CAP_SECONDS + 1,
        reason="test",
    )

    assert "8.8.8.7" in manager.banned_ips
    expiry = manager.banned_ips["8.8.8.7"]
    assert expiry == pytest.approx(
        time.time() + manager.LOCAL_CACHE_TTL_CAP_SECONDS + 1, abs=2
    )
    assert manager.is_ip_banned("8.8.8.7") is True
    assert not [r for r in caplog.records if r.levelno == logging.WARNING]


def test_ban_zero_or_negative_duration_raises() -> None:
    manager = IPBanManager()
    manager.redis_handler = None

    with pytest.raises(ValueError):
        manager.ban_ip("10.0.0.8", duration=0, reason="test")

    with pytest.raises(ValueError):
        manager.ban_ip("10.0.0.9", duration=-1, reason="test")


def test_ban_longer_than_cap_succeeds_when_redis_available() -> None:
    from unittest.mock import MagicMock

    manager = IPBanManager()
    manager.redis_handler = MagicMock()
    manager.banned_ips.clear()

    duration = manager.LOCAL_CACHE_TTL_CAP_SECONDS + 1
    manager.ban_ip("10.0.0.10", duration=duration, reason="test")

    assert "10.0.0.10" in manager.banned_ips
    manager.redis_handler.set_key.assert_called_once()
    assert manager.redis_handler.set_key.call_args.kwargs["ttl"] == duration


class _FailingRedisHandler:
    def set_key(self, *args: object, **kwargs: object) -> None:
        raise Exception("down")


def test_ban_exact_ip_longer_than_cap_keeps_its_duration_when_redis_set_key_fails(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = IPBanManager()
    manager.redis_handler = _FailingRedisHandler()
    manager.banned_ips.clear()

    caplog.set_level(logging.WARNING, logger="guard_core.sync.handlers.ipban")
    manager.ban_ip(
        "8.8.8.11",
        duration=manager.LOCAL_CACHE_TTL_CAP_SECONDS + 1,
        reason="test",
    )

    assert "8.8.8.11" in manager.banned_ips
    expiry = manager.banned_ips["8.8.8.11"]
    assert expiry == pytest.approx(
        time.time() + manager.LOCAL_CACHE_TTL_CAP_SECONDS + 1, abs=2
    )

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    message = warnings[0].getMessage()
    assert "request failed" in message
    assert "this process only" in message


def test_ban_exact_ip_at_cap_warns_that_it_is_kept_in_this_process(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = IPBanManager()
    manager.redis_handler = _FailingRedisHandler()
    manager.banned_ips.clear()

    caplog.set_level(logging.WARNING, logger="guard_core.sync.handlers.ipban")
    manager.ban_ip(
        "8.8.8.12",
        duration=manager.LOCAL_CACHE_TTL_CAP_SECONDS,
        reason="test",
    )

    assert "8.8.8.12" in manager.banned_ips
    expiry = manager.banned_ips["8.8.8.12"]
    assert expiry == pytest.approx(
        time.time() + manager.LOCAL_CACHE_TTL_CAP_SECONDS, abs=2
    )

    [warning] = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert "this process only" in warning.getMessage()
