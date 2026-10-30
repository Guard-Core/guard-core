import time

from guard_core.sync.handlers.ipban_handler import IPBanManager


def test_an_expired_exact_ban_does_not_hide_a_live_network_ban() -> None:
    manager = IPBanManager._fresh()
    manager.ban_ip("203.0.113.7", 1, "manual")
    manager.ban_ip("203.0.113.0/24", 3600, "manual")
    assert manager.is_ip_banned("203.0.113.7")
    manager.banned_ips["203.0.113.7"] = time.time() - 1

    assert manager.is_ip_banned("203.0.113.7") is True
    assert manager.is_ip_banned("203.0.113.7") is True


def test_an_expired_exact_ban_alone_is_not_a_ban() -> None:
    manager = IPBanManager._fresh()
    manager.ban_ip("198.51.100.4", 1, "manual")
    manager.banned_ips["198.51.100.4"] = time.time() - 1

    assert manager.is_ip_banned("198.51.100.4") is False
