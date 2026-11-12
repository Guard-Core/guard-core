import os
import time
from collections.abc import AsyncGenerator, Generator
from unittest.mock import patch

import pytest

from guard_core.handlers import _ipban_carve
from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import suite_redis_prefix

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
IDENTITY = "2001:db8:0:1::/64"
HOST = "2001:db8:0:1::5"
NEIGHBOUR = "2001:db8:0:1::6"


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


@pytest.fixture
async def live_redis() -> AsyncGenerator[RedisManager, None]:
    config = SecurityConfig(
        redis_url=REDIS_URL, redis_prefix=suite_redis_prefix("wp6-carve")
    )
    manager = RedisManager(config)
    await manager.initialize()
    yield manager
    await manager.delete_pattern("*")
    await manager.close()


def _manager(whitelist: list[str], **settings: object) -> IPBanManager:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.config = SecurityConfig(enable_redis=False, whitelist=whitelist, **settings)
    return manager


async def test_a_whitelisted_host_is_not_caught_by_its_neighbours_ban() -> None:
    manager = _manager([HOST])
    await manager.ban_ip(IDENTITY, 600, "t", grouped=True)

    assert await manager.is_ip_banned(HOST) is False
    assert await manager.is_ip_banned(NEIGHBOUR) is True


async def test_a_whitelisted_range_longer_than_the_prefix_is_one_identity() -> None:
    manager = _manager(["2001:db8:0:1:0:0:0:0/72"])
    await manager.ban_ip(IDENTITY, 600, "t", grouped=True)

    assert await manager.is_ip_banned(HOST) is False
    assert await manager.is_ip_banned("2001:db8:0:1:0:ff::9") is False
    assert await manager.is_ip_banned("2001:db8:0:1:ff00::9") is True


async def test_a_whitelisted_host_that_attacks_is_banned_at_its_own_identity() -> None:
    manager = _manager([HOST])
    await manager.ban_ip(f"{HOST}/128", 600, "t", grouped=True)

    assert await manager.is_ip_banned(HOST) is True
    assert await manager.is_ip_banned(NEIGHBOUR) is False


async def test_a_whitelisted_range_that_attacks_is_banned_as_one_identity() -> None:
    manager = _manager(["2001:db8:0:1:0:0:0:0/72"])
    await manager.ban_ip("2001:db8:0:1::/72", 600, "t", grouped=True)

    assert await manager.is_ip_banned(HOST) is True
    assert await manager.is_ip_banned("2001:db8:0:1:0:ff::9") is True
    assert await manager.is_ip_banned("2001:db8:0:1:ff00::9") is False


async def test_a_wider_whitelist_does_not_act_as_an_unban() -> None:
    manager = _manager(["2001:db8::/48"])
    await manager.ban_ip(IDENTITY, 600, "t", grouped=True)

    assert await manager.is_ip_banned(HOST) is True


async def test_an_operator_cidr_ban_still_denies_a_whitelisted_host() -> None:
    manager = _manager([HOST])
    await manager.ban_ip("2001:db8:0:1::/72", 600, "operator")

    assert await manager.is_ip_banned(HOST) is True


async def test_a_6to4_host_is_carved_inside_its_slash_48_identity() -> None:
    manager = _manager(["2002:c000:204:100::/56"])
    await manager.ban_ip("2002:c000:204::/48", 600, "t", grouped=True)

    assert await manager.is_ip_banned("2002:c000:204:101::7") is False
    assert await manager.is_ip_banned("2002:c000:204:200::7") is True


async def test_the_whitelist_match_runs_only_for_native_ipv6_with_a_whitelist() -> None:
    manager = _manager([HOST])
    with patch(
        "guard_core.handlers._ipban_lookup.most_specific_whitelist_entry"
    ) as match:
        assert await manager.is_ip_banned("198.51.100.1") is False
        assert await manager.is_ip_banned("64:ff9b:1::808:808") is False

    match.assert_not_called()


async def test_an_empty_whitelist_never_runs_the_match() -> None:
    manager = _manager([])
    await manager.ban_ip(IDENTITY, 600, "t", grouped=True)
    with patch(
        "guard_core.handlers._ipban_lookup.most_specific_whitelist_entry"
    ) as match:
        assert await manager.is_ip_banned(HOST) is True

    match.assert_not_called()


async def test_the_carve_works_through_redis_on_another_worker(
    live_redis: RedisManager,
) -> None:
    writer = _manager([HOST])
    writer.redis_handler = live_redis
    await writer.ban_ip(IDENTITY, 600, "t", grouped=True)
    IPBanManager._instance = None
    reader = _manager([HOST])
    reader.redis_handler = live_redis

    assert await reader.is_ip_banned(HOST) is False
    assert await reader.is_ip_banned(NEIGHBOUR) is True


async def test_removing_a_carved_whitelist_moves_the_ban_to_the_base_identity() -> None:
    manager = _manager([])
    carve = "2002:c000:204:100::/56"
    manager.banned_ips[carve] = time.time() + 600
    manager.banned_ips["2002:c000:204::/48"] = time.time() + 100

    moved = await manager.rewrite_carved_bans_without_whitelist()

    assert moved == 1
    assert carve not in manager.banned_ips
    assert manager.banned_ips["2002:c000:204::/48"] == pytest.approx(
        time.time() + 600, abs=3
    )
    assert await manager.is_ip_banned("2002:c000:204:101::7") is True


async def test_a_carve_that_the_whitelist_still_produces_is_left_alone() -> None:
    manager = _manager(["2002:c000:204:100::/56"])
    carve = "2002:c000:204:100::/56"
    manager.banned_ips[carve] = time.time() + 600

    assert await manager.rewrite_carved_bans_without_whitelist() == 0
    assert carve in manager.banned_ips


async def test_a_plain_slash_64_identity_is_never_rewritten() -> None:
    manager = _manager([])
    manager.banned_ips[IDENTITY] = time.time() + 600

    assert await manager.rewrite_carved_bans_without_whitelist() == 0
    assert IDENTITY in manager.banned_ips


async def test_an_operator_slash_72_ban_survives_the_rewrite_unchanged() -> None:
    manager = _manager([])
    await manager.ban_ip("2001:db8:0:1::/72", 600, "operator")

    await manager.rewrite_carved_bans_without_whitelist()

    assert [str(network) for network, _ in manager.banned_networks] == [
        "2001:db8:0:1::/72"
    ]


async def test_the_redis_rewrite_keeps_the_remaining_ttl(
    live_redis: RedisManager,
) -> None:
    manager = _manager([])
    manager.redis_handler = live_redis
    carve = "2002:c000:204:100::/56"
    await live_redis.set_key(
        "banned_identities", carve, str(time.time() + 300), ttl=300
    )

    moved = await manager.rewrite_carved_bans_without_whitelist()

    assert moved == 1
    assert not await live_redis.get_key("banned_identities", carve)
    assert await live_redis.get_key("banned_identities", "2002:c000:204::/48")
    async with live_redis.get_connection() as conn:
        key = f"{live_redis.config.redis_prefix}banned_identities:2002:c000:204::/48"
        assert 250_000 < await conn.pttl(key) <= 300_000


async def test_the_startup_whitelist_scan_runs_the_rewrite(
    live_redis: RedisManager,
) -> None:
    from guard_core.core.initialization._whitelist_strikes import (
        reset_strikes_for_changed_whitelist,
    )

    manager = _manager([])
    manager.redis_handler = live_redis
    carve = "2002:c000:204:100::/56"
    await live_redis.set_key(
        "banned_identities", carve, str(time.time() + 300), ttl=300
    )
    config = SecurityConfig(enable_redis=False, whitelist=["203.0.113.0/24"])

    await reset_strikes_for_changed_whitelist(config, live_redis, manager)

    assert await live_redis.get_key("banned_identities", "2002:c000:204::/48")
    assert not await live_redis.get_key("banned_identities", carve)


async def test_the_real_initialization_gives_the_ban_manager_the_whitelist() -> None:
    from guard_core.core.initialization.handler_initializer import HandlerInitializer
    from guard_core.handlers.ipban_handler import ip_ban_manager

    config = SecurityConfig(enable_redis=False, lazy_init=False, whitelist=[HOST])
    saved_config = ip_ban_manager.config
    try:
        await HandlerInitializer(config=config).initialize_redis_handlers()
        await ip_ban_manager.ban_ip(IDENTITY, 600, "t", grouped=True)

        assert ip_ban_manager.config is config
        assert await ip_ban_manager.is_ip_banned(HOST) is False
        assert await ip_ban_manager.is_ip_banned(NEIGHBOUR) is True
    finally:
        await ip_ban_manager.reset()
        ip_ban_manager.config = saved_config


async def test_the_redis_rewrite_does_not_extend_a_ban_by_time_lost_mid_move(
    live_redis: RedisManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _manager([])
    manager.redis_handler = live_redis
    prefix = live_redis.config.redis_prefix
    carve, base = "2002:c000:204:100::/56", "2002:c000:204::/48"
    async with live_redis.get_connection() as conn:
        await conn.set(f"{prefix}banned_identities:{carve}", "9999999999.5", ex=600)
        await conn.set(
            f"{prefix}ban_floors:banned_identities:{carve}", "9999999999.5", px=300_000
        )
    real_plan = _ipban_carve._plan_floor_move

    async def plan_then_stall(*args: object, **kw: object) -> object:
        plan = await real_plan(*args, **kw)
        time.sleep(1.5)
        return plan

    monkeypatch.setattr(_ipban_carve, "_plan_floor_move", plan_then_stall)
    assert await manager.rewrite_carved_bans_without_whitelist() == 1
    monkeypatch.undo()

    async with live_redis.get_connection() as conn:
        ban_pttl = await conn.pttl(f"{prefix}banned_identities:{base}")
        floor_pttl = await conn.pttl(f"{prefix}ban_floors:banned_identities:{base}")
    assert ban_pttl <= 600_000 - 1_400
    assert floor_pttl <= 300_000 - 1_400
