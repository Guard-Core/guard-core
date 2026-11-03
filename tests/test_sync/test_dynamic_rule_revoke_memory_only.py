import time
from collections.abc import Generator
from contextlib import AbstractContextManager
from unittest.mock import MagicMock, patch

import pytest

from guard_core.sync.handlers._ipban_cache import _BanStore
from guard_core.sync.handlers.ipban_handler import IPBanManager, ip_ban_manager
from tests.test_sync.test_dynamic_rule_revoke_owned_only import (
    INSIDE_NETWORK,
    IP,
    NETWORK,
    OTHER,
    Fleet,
    _close_fleet,
    _open_fleet,
)


@pytest.fixture
def redis_fleet() -> Generator[Fleet, None]:
    opened = _open_fleet(True)
    yield opened
    ip_ban_manager.set_capacity(IPBanManager.MAX_LOCAL_BANS)
    _close_fleet(opened)


def _failing_write(fleet: Fleet) -> AbstractContextManager[object]:
    return patch.object(
        fleet.redis,
        "write_ban_extending_only",
        MagicMock(side_effect=RuntimeError("redis write failed")),
    )


def _local_seconds_left(key: str) -> float:
    return ip_ban_manager.banned_ips[key] - time.time()


def _network_seconds_left() -> list[float]:
    return [until - time.time() for _, until in ip_ban_manager.banned_networks]


@pytest.mark.parametrize("foreign", [86400, 60])
def test_a_foreign_ip_ban_held_in_this_process_survives_the_revoke(
    redis_fleet: Fleet, foreign: int
) -> None:
    redis_fleet.apply(1, [IP])
    with _failing_write(redis_fleet):
        ip_ban_manager.ban_ip(IP, foreign, "auto_ban")

    redis_fleet.apply(2, [OTHER])

    assert ip_ban_manager.is_ip_banned(IP)
    assert foreign - 5 < _local_seconds_left(IP) <= foreign
    assert redis_fleet.expiry(IP) is None


@pytest.mark.parametrize("foreign", [86400, 60])
def test_a_foreign_network_ban_held_in_this_process_survives_the_revoke(
    redis_fleet: Fleet, foreign: int
) -> None:
    redis_fleet.apply(1, [NETWORK])
    with _failing_write(redis_fleet):
        ip_ban_manager.ban_ip(NETWORK, foreign, "operator")

    redis_fleet.apply(2, [OTHER])

    assert ip_ban_manager.is_ip_banned(INSIDE_NETWORK)
    (left,) = _network_seconds_left()
    assert foreign - 5 < left <= foreign


@pytest.mark.parametrize("foreign", [86400, 60])
def test_a_foreign_ban_held_here_before_a_backed_rule_write_survives(
    redis_fleet: Fleet, foreign: int
) -> None:
    with _failing_write(redis_fleet):
        ip_ban_manager.ban_ip(IP, foreign, "auto_ban")
    redis_fleet.apply(1, [IP])

    redis_fleet.apply(2, [OTHER])

    assert ip_ban_manager.is_ip_banned(IP)
    assert foreign - 5 < _local_seconds_left(IP) <= foreign


def test_the_longest_of_two_failed_foreign_writes_is_the_one_kept(
    redis_fleet: Fleet,
) -> None:
    redis_fleet.apply(1, [IP])
    with _failing_write(redis_fleet):
        ip_ban_manager.ban_ip(IP, 86400, "auto_ban")
        ip_ban_manager.ban_ip(IP, 60, "auto_ban")

    redis_fleet.apply(2, [OTHER])

    assert 86400 - 5 < _local_seconds_left(IP) <= 86400


def test_the_rules_own_failed_write_is_still_lifted_by_its_revoke(
    redis_fleet: Fleet,
) -> None:
    with _failing_write(redis_fleet):
        redis_fleet.apply(1, [IP, NETWORK])

    redis_fleet.apply(2, [OTHER])

    assert not ip_ban_manager.is_ip_banned(IP)
    assert not ip_ban_manager.is_ip_banned(INSIDE_NETWORK)


def test_an_identity_write_that_fails_records_nothing(
    redis_fleet: Fleet,
) -> None:
    with _failing_write(redis_fleet):
        ip_ban_manager.ban_ip("2001:db8:1::/64", 3600, "auto_ban", grouped=True)

    assert isinstance(ip_ban_manager.banned_ips, _BanStore)
    assert ip_ban_manager.banned_ips._foreign_memory == {}


def test_the_ip_records_never_outnumber_the_store_capacity(
    redis_fleet: Fleet,
) -> None:
    ip_ban_manager.set_capacity(3)
    with _failing_write(redis_fleet):
        for index in range(12):
            ip_ban_manager.ban_ip(f"198.51.100.{index + 1}", 3600, "auto_ban")

    assert isinstance(ip_ban_manager.banned_ips, _BanStore)
    assert len(ip_ban_manager.banned_ips) == 3
    assert len(ip_ban_manager.banned_ips._foreign_memory) <= 3


def test_the_network_records_never_outnumber_the_store_capacity(
    redis_fleet: Fleet,
) -> None:
    with (
        patch.object(ip_ban_manager, "MAX_LOCAL_BANS", 2),
        _failing_write(redis_fleet),
    ):
        for index in range(6):
            ip_ban_manager.ban_ip(f"203.0.{index}.0/24", 60 + index, "operator")

    assert len(ip_ban_manager._foreign_network_expiries) == 2


def test_unban_then_revoke_leaves_the_ip_and_the_network_unbanned(
    redis_fleet: Fleet,
) -> None:
    redis_fleet.apply(1, [IP, NETWORK])
    with _failing_write(redis_fleet):
        ip_ban_manager.ban_ip(IP, 86400, "auto_ban")
        ip_ban_manager.ban_ip(NETWORK, 86400, "operator")
    ip_ban_manager.unban_ip(IP)
    ip_ban_manager.unban_ip(NETWORK)

    redis_fleet.apply(2, [OTHER])

    assert not ip_ban_manager.is_ip_banned(IP)
    assert not ip_ban_manager.is_ip_banned(INSIDE_NETWORK)


def test_whitelist_then_revoke_leaves_the_ip_unbanned(
    redis_fleet: Fleet,
) -> None:
    redis_fleet.apply(1, [IP])
    with _failing_write(redis_fleet):
        ip_ban_manager.ban_ip(IP, 86400, "auto_ban")

    redis_fleet.apply(2, [OTHER], whitelist=[IP])

    assert not ip_ban_manager.is_ip_banned(IP)


def test_unbanning_a_range_and_a_reset_clear_the_records(
    redis_fleet: Fleet,
) -> None:
    with _failing_write(redis_fleet):
        ip_ban_manager.ban_ip(NETWORK, 3600, "operator")
        ip_ban_manager.ban_ip(IP, 3600, "auto_ban")
    assert ip_ban_manager._foreign_network_expiries

    ip_ban_manager.unban_inside([NETWORK])
    assert ip_ban_manager._foreign_network_expiries == {}

    with _failing_write(redis_fleet):
        ip_ban_manager.ban_ip(NETWORK, 3600, "operator")
    ip_ban_manager.reset()
    assert ip_ban_manager._foreign_network_expiries == {}
    assert isinstance(ip_ban_manager.banned_ips, _BanStore)
    assert ip_ban_manager.banned_ips._foreign_memory == {}


def test_an_expired_record_is_not_kept(redis_fleet: Fleet) -> None:
    redis_fleet.apply(1, [IP, NETWORK])
    with _failing_write(redis_fleet):
        ip_ban_manager.ban_ip(IP, 60, "auto_ban")
        ip_ban_manager.ban_ip(NETWORK, 60, "operator")
    assert isinstance(ip_ban_manager.banned_ips, _BanStore)
    ip_ban_manager.banned_ips._foreign_memory[IP] = time.time() - 1
    ip_ban_manager._foreign_network_expiries[NETWORK] = time.time() - 1

    redis_fleet.apply(2, [OTHER])

    assert not ip_ban_manager.is_ip_banned(IP)
    assert not ip_ban_manager.is_ip_banned(INSIDE_NETWORK)


def test_a_plain_mapping_store_records_nothing_and_the_revoke_lifts_the_ip(
    redis_fleet: Fleet,
) -> None:
    redis_fleet.apply(1, [IP])
    with patch.object(ip_ban_manager, "banned_ips", {}), _failing_write(redis_fleet):
        ip_ban_manager.ban_ip(IP, 86400, "auto_ban")

        redis_fleet.apply(2, [OTHER])

        assert IP not in ip_ban_manager.banned_ips
