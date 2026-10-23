import logging
from collections.abc import Generator
from types import SimpleNamespace

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.ipban_handler import IPBanManager

TRUSTED_PROXY_EXACT = "203.0.113.10"
TRUSTED_PROXY_CIDR = "198.51.100.0/24"
TRUSTED_PROXY_MEMBER = "198.51.100.42"


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


def _config() -> SyncSecurityConfig:
    return SyncSecurityConfig(trusted_proxies=(TRUSTED_PROXY_EXACT, TRUSTED_PROXY_CIDR))


def _manager_with_config() -> IPBanManager:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.config = _config()
    return manager


def test_ban_loopback_ipv4_is_refused(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager_with_config()

    caplog.set_level(logging.WARNING, logger="guard_core.sync.handlers.ipban")
    result = manager.ban_ip("127.0.0.1", duration=300, reason="threshold_exceeded")

    assert result is False
    assert "127.0.0.1" not in manager.banned_ips
    assert manager.is_ip_banned("127.0.0.1") is False
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("127.0.0.1" in r.getMessage() for r in warnings)


def test_ban_loopback_ipv6_is_refused(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager_with_config()

    caplog.set_level(logging.WARNING, logger="guard_core.sync.handlers.ipban")
    manager.ban_ip("::1", duration=300, reason="threshold_exceeded")

    assert "::1" not in manager.banned_ips
    assert manager.is_ip_banned("::1") is False
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("::1" in r.getMessage() for r in warnings)


def test_ban_trusted_proxy_member_is_refused(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager_with_config()

    caplog.set_level(logging.WARNING, logger="guard_core.sync.handlers.ipban")
    manager.ban_ip(TRUSTED_PROXY_EXACT, duration=300, reason="threshold_exceeded")

    assert TRUSTED_PROXY_EXACT not in manager.banned_ips
    assert manager.is_ip_banned(TRUSTED_PROXY_EXACT) is False
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any(TRUSTED_PROXY_EXACT in r.getMessage() for r in warnings)


def test_ban_trusted_proxy_cidr_member_is_refused(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager_with_config()

    caplog.set_level(logging.WARNING, logger="guard_core.sync.handlers.ipban")
    manager.ban_ip(TRUSTED_PROXY_MEMBER, duration=300, reason="threshold_exceeded")

    assert TRUSTED_PROXY_MEMBER not in manager.banned_ips
    assert manager.is_ip_banned(TRUSTED_PROXY_MEMBER) is False
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any(TRUSTED_PROXY_MEMBER in r.getMessage() for r in warnings)


def test_ban_cidr_overlapping_loopback_is_refused(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager_with_config()

    caplog.set_level(logging.WARNING, logger="guard_core.sync.handlers.ipban")
    result = manager.ban_ip("127.0.0.0/8", duration=300, reason="threshold_exceeded")

    assert result is False
    assert manager.banned_networks == []
    assert manager.is_ip_banned("127.0.0.5") is False
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("127.0.0.0/8" in r.getMessage() for r in warnings)


def test_ban_cidr_overlapping_trusted_proxy_is_refused(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager_with_config()

    caplog.set_level(logging.WARNING, logger="guard_core.sync.handlers.ipban")
    manager.ban_ip(TRUSTED_PROXY_CIDR, duration=300, reason="threshold_exceeded")

    assert manager.banned_networks == []
    assert manager.is_ip_banned(TRUSTED_PROXY_MEMBER) is False
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any(TRUSTED_PROXY_CIDR in r.getMessage() for r in warnings)


def test_ban_cidr_partially_overlapping_trusted_proxy_is_refused() -> None:
    manager = _manager_with_config()

    manager.ban_ip("198.51.100.128/25", duration=300, reason="threshold_exceeded")

    assert manager.banned_networks == []
    assert manager.is_ip_banned("198.51.100.200") is False


def test_ban_loopback_without_any_config_is_still_refused() -> None:
    manager = IPBanManager()
    manager.redis_handler = None

    manager.ban_ip("127.0.0.1", duration=300, reason="threshold_exceeded")

    assert "127.0.0.1" not in manager.banned_ips
    assert manager.is_ip_banned("127.0.0.1") is False


def test_ban_refused_target_never_reaches_redis() -> None:
    from unittest.mock import MagicMock

    manager = IPBanManager()
    manager.config = _config()
    manager.redis_handler = MagicMock()

    manager.ban_ip("127.0.0.1", duration=300, reason="threshold_exceeded")

    manager.redis_handler.set_key.assert_not_called()


def test_ban_with_malformed_trusted_proxies_entry_does_not_raise() -> None:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.config = SimpleNamespace(trusted_proxies=["not-an-ip-or-cidr"])

    manager.ban_ip("8.8.8.8", duration=300, reason="threshold_exceeded")

    assert manager.is_ip_banned("8.8.8.8") is True


def test_ban_public_ip_with_config_still_succeeds() -> None:
    manager = _manager_with_config()

    result = manager.ban_ip("8.8.8.8", duration=300, reason="threshold_exceeded")

    assert result is True
    assert manager.is_ip_banned("8.8.8.8") is True


def test_ban_public_cidr_with_config_still_succeeds() -> None:
    manager = _manager_with_config()

    result = manager.ban_ip("8.8.8.0/24", duration=300, reason="threshold_exceeded")

    assert result is True
    assert manager.is_ip_banned("8.8.8.5") is True


def test_ban_loopback_over_cap_duration_is_refused_not_clamped(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = IPBanManager()
    manager.redis_handler = None

    caplog.set_level(logging.WARNING, logger="guard_core.sync.handlers.ipban")
    manager.ban_ip(
        "127.0.0.1",
        duration=manager.LOCAL_CACHE_TTL_CAP_SECONDS + 3600,
        reason="threshold_exceeded",
    )

    assert "127.0.0.1" not in manager.banned_ips
    assert manager.is_ip_banned("127.0.0.1") is False

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    message = warnings[0].getMessage()
    assert "loopback" in message
    assert "clamped" not in message
    assert "shortened" not in message


def test_ban_private_ipv4_warns_but_still_bans(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager_with_config()

    caplog.set_level(logging.WARNING, logger="guard_core.sync.handlers.ipban")
    manager.ban_ip("10.0.0.5", duration=300, reason="threshold_exceeded")

    assert manager.is_ip_banned("10.0.0.5") is True
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any(
        "Banning private IP range" in r.getMessage() and "10.0.0.5" in r.getMessage()
        for r in warnings
    )


def test_ban_private_cidr_warns_but_still_bans(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager_with_config()

    caplog.set_level(logging.WARNING, logger="guard_core.sync.handlers.ipban")
    manager.ban_ip("192.168.0.0/24", duration=300, reason="threshold_exceeded")

    assert manager.is_ip_banned("192.168.0.10") is True
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any(
        "Banning private IP range" in r.getMessage()
        and "192.168.0.0/24" in r.getMessage()
        for r in warnings
    )


def test_ban_private_ipv6_ula_warns_but_still_bans(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager_with_config()

    caplog.set_level(logging.WARNING, logger="guard_core.sync.handlers.ipban")
    manager.ban_ip("fd00::1", duration=300, reason="threshold_exceeded")

    assert manager.is_ip_banned("fd00::1") is True
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any(
        "Banning private IP range" in r.getMessage() and "fd00::1" in r.getMessage()
        for r in warnings
    )


def test_ban_public_ip_emits_no_private_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager_with_config()

    caplog.set_level(logging.WARNING, logger="guard_core.sync.handlers.ipban")
    manager.ban_ip("8.8.8.8", duration=300, reason="threshold_exceeded")

    assert manager.is_ip_banned("8.8.8.8") is True
    assert not any("Banning private IP range" in r.getMessage() for r in caplog.records)


def test_ban_loopback_does_not_emit_private_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager_with_config()

    caplog.set_level(logging.WARNING, logger="guard_core.sync.handlers.ipban")
    manager.ban_ip("127.0.0.1", duration=300, reason="threshold_exceeded")

    assert manager.is_ip_banned("127.0.0.1") is False
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("127.0.0.1" in r.getMessage() for r in warnings)
    assert not any("Banning private IP range" in r.getMessage() for r in warnings)


def test_ban_invalid_ip_emits_no_private_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager_with_config()

    caplog.set_level(logging.WARNING, logger="guard_core.sync.handlers.ipban")
    with pytest.raises(ValueError):
        manager.ban_ip("not-an-ip", duration=300, reason="threshold_exceeded")

    assert not any("Banning private IP range" in r.getMessage() for r in caplog.records)
