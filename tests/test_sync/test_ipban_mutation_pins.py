import time
from collections.abc import Generator
from ipaddress import ip_network
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.app_managers import mark_shared_by_apps
from guard_core.sync.handlers._ipban_cache import _BanStore
from guard_core.sync.handlers.ipban_handler import IPBanManager


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


def _manager() -> IPBanManager:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.config = SyncSecurityConfig(enable_redis=False)
    return manager


def test_a_network_ban_does_not_inherit_another_networks_longer_expiry() -> None:
    manager = _manager()

    manager.ban_ip("203.0.113.0/24", 1000, "operator")
    manager.ban_ip("198.51.100.0/24", 10, "operator")

    expiries = {str(network): until for network, until in manager.banned_networks}
    assert expiries["198.51.100.0/24"] < time.time() + 100
    assert expiries["203.0.113.0/24"] > time.time() + 900


def test_remembering_a_network_ban_defaults_to_not_owned_by_a_rule() -> None:
    manager = _manager()
    network = ip_network("203.0.113.0/24")

    manager._remember_network_ban(network, time.time() + 60)

    assert "banned_networks:203.0.113.0/24" not in manager._rule_owned_expiries


def test_a_ban_whose_redis_write_failed_is_marked_memory_only() -> None:
    manager = _manager()
    manager.redis_handler = Mock(
        write_ban_extending_only=MagicMock(side_effect=RuntimeError("down"))
    )

    manager.ban_ip("203.0.113.9", 60)

    assert isinstance(manager.banned_ips, _BanStore)
    assert manager.banned_ips.is_memory_only("203.0.113.9")


def test_an_unscoped_ban_on_a_shared_manager_fans_out_across_its_apps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _manager()
    first = SyncSecurityConfig(enable_redis=False)
    second = SyncSecurityConfig(enable_redis=False)
    mark_shared_by_apps(manager, first, second)
    across = MagicMock(return_value=True)
    monkeypatch.setattr(manager, "_ban_ip_across_sharing_apps", across)

    assert manager.ban_ip("203.0.113.9", 60, "operator") is True

    across.assert_called_once_with("203.0.113.9", 60, "operator", False)


def test_a_scoped_ban_on_a_shared_manager_stays_in_its_own_app(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _manager()
    first = SyncSecurityConfig(enable_redis=False)
    second = SyncSecurityConfig(enable_redis=False)
    mark_shared_by_apps(manager, first, second)
    across = MagicMock(return_value=True)
    monkeypatch.setattr(manager, "_ban_ip_across_sharing_apps", across)

    assert manager.ban_ip("203.0.113.9", 60, "operator", config=first) is True

    across.assert_not_called()
