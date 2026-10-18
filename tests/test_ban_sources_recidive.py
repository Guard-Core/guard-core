import time
from collections.abc import Generator

import pytest

from guard_core.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.models import SecurityConfig

IPV4 = "8.8.8.8"
IPV6_CLIENT = "2001:db8:0:1::5"
IPV6_IDENTITY = "2001:db8:0:1::/64"
BASE = 100


@pytest.fixture
def manager(monkeypatch: pytest.MonkeyPatch) -> Generator[IPBanManager, None, None]:
    IPBanManager._instance = None
    ban_manager = IPBanManager()
    ban_manager.redis_handler = None
    ban_manager.config = SecurityConfig(enable_redis=False, enable_recidive=True)
    monkeypatch.setattr("guard_core.handlers.ipban_handler.ip_ban_manager", ban_manager)
    yield ban_manager
    IPBanManager._instance = None


def _tracker() -> BehaviorTracker:
    return BehaviorTracker(SecurityConfig(enable_redis=False, enable_recidive=True))


def _rule() -> BehaviorRule:
    return BehaviorRule(rule_type="usage", threshold=1, action="ban", ban_duration=BASE)


def _lapse(manager: IPBanManager, key: str) -> None:
    manager.banned_ips[key] = time.time() - 1


def _remaining(manager: IPBanManager, key: str) -> float:
    return manager.banned_ips[key] - time.time()


async def _behavioral_ban(client_ip: str) -> None:
    await _tracker()._execute_ban_action(client_ip, "details", _rule())


async def test_a_manual_ban_twice_inside_the_window_keeps_its_duration(
    manager: IPBanManager,
) -> None:
    await manager.ban_ip(IPV4, BASE, "manual")
    _lapse(manager, IPV4)

    await manager.ban_ip(IPV4, BASE, "manual")

    assert 90 < _remaining(manager, IPV4) <= BASE
    assert manager.recidive_history == {}


async def test_a_threshold_ban_twice_gives_twice_the_duration(
    manager: IPBanManager,
) -> None:
    await manager._ban_ip_escalating(IPV4, BASE, "rate_limit_exceeded")
    _lapse(manager, IPV4)

    await manager._ban_ip_escalating(IPV4, BASE, "rate_limit_exceeded")

    assert 190 < _remaining(manager, IPV4) <= 2 * BASE


async def test_a_behavioral_ban_twice_gives_twice_the_duration(
    manager: IPBanManager,
) -> None:
    await _behavioral_ban(IPV4)
    _lapse(manager, IPV4)

    await _behavioral_ban(IPV4)

    assert 190 < _remaining(manager, IPV4) <= 2 * BASE


async def test_a_behavioral_ban_then_a_threshold_ban_gives_twice_for_ipv4(
    manager: IPBanManager,
) -> None:
    await _behavioral_ban(IPV4)
    _lapse(manager, IPV4)

    await manager._ban_ip_escalating(IPV4, BASE, "rate_limit_exceeded")

    assert 190 < _remaining(manager, IPV4) <= 2 * BASE


async def test_a_behavioral_ban_then_a_threshold_ban_gives_twice_for_a_slash_64(
    manager: IPBanManager,
) -> None:
    await _behavioral_ban(IPV6_CLIENT)
    assert IPV6_IDENTITY in manager.banned_ips
    _lapse(manager, IPV6_IDENTITY)

    await manager._ban_ip_escalating(
        IPV6_IDENTITY, BASE, "rate_limit_exceeded", grouped=True
    )

    assert 190 < _remaining(manager, IPV6_IDENTITY) <= 2 * BASE


async def test_a_behavioral_ban_denies_every_address_of_the_network(
    manager: IPBanManager,
) -> None:
    await _behavioral_ban(IPV6_CLIENT)

    assert await manager.is_ip_banned("2001:db8:0:1:ffff::9") is True
    assert await manager.is_ip_banned("2001:db8:0:2::5") is False


async def test_a_behavioral_ban_at_prefix_128_bans_the_address(
    manager: IPBanManager,
) -> None:
    manager.config = SecurityConfig(enable_redis=False, ipv6_prefix_length=128)
    tracker = BehaviorTracker(manager.config)

    await tracker._execute_ban_action(IPV6_CLIENT, "details", _rule())

    assert IPV6_CLIENT in manager.banned_ips


async def test_a_dynamic_rule_ban_never_escalates_or_counts(
    manager: IPBanManager,
) -> None:
    await manager.ban_ip(IPV4, BASE, "dynamic_rule")
    _lapse(manager, IPV4)

    await manager.ban_ip(IPV4, BASE, "dynamic_rule")

    assert 90 < _remaining(manager, IPV4) <= BASE
    assert manager.recidive_history == {}
