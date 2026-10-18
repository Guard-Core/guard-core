import ipaddress
import os
import time
import uuid
from collections.abc import AsyncGenerator, Generator
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import pytest

from guard_core._utils.ip_extraction import _client_identity
from guard_core.handlers._ipban_coverage import NetworkCoverage
from guard_core.handlers._ipban_queries import _strike_key_inside
from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
IDENTITY = "2001:db8:0:1::/64"
HOST = "2001:db8:0:1::5"
NEIGHBOUR_HOST = "2001:db8:0:2::5"


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


@pytest.fixture
async def live_redis() -> AsyncGenerator[RedisManager, None]:
    config = SecurityConfig(
        redis_url=REDIS_URL, redis_prefix=f"wp6-id:{uuid.uuid4().hex}:"
    )
    manager = RedisManager(config)
    await manager.initialize()
    yield manager
    await manager.delete_pattern("*")
    await manager.close()


def _manager(**settings: Any) -> IPBanManager:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.config = SecurityConfig(enable_redis=False, **settings)
    return manager


async def test_a_grouped_ban_denies_every_address_of_the_identity() -> None:
    manager = _manager()

    assert await manager.ban_ip(IDENTITY, 600, "rate_limit_exceeded", grouped=True)

    assert await manager.is_ip_banned(HOST) is True
    assert await manager.is_ip_banned("2001:db8:0:1:ffff::9") is True
    assert await manager.is_ip_banned(NEIGHBOUR_HOST) is False


async def test_a_grouped_ban_is_not_an_operator_network_ban() -> None:
    manager = _manager()

    await manager.ban_ip(IDENTITY, 600, "threshold_exceeded", grouped=True)

    assert manager.banned_networks == []
    assert IDENTITY in manager.banned_ips


async def test_an_operator_ban_of_exactly_a_slash_64_keeps_containment() -> None:
    manager = _manager()

    await manager.ban_ip(IDENTITY, 600, "operator")

    assert [str(network) for network, _ in manager.banned_networks] == [IDENTITY]
    assert IDENTITY not in manager.banned_ips
    assert await manager.is_ip_banned(HOST) is True


async def test_a_grouped_ban_sends_an_ip_banned_event_for_the_identity() -> None:
    manager = _manager()
    manager.agent_handler = Mock(send_event=AsyncMock())

    await manager.ban_ip(IDENTITY, 600, "rate_limit_exceeded", grouped=True)

    [event] = [call.args[0] for call in manager.agent_handler.send_event.call_args_list]
    assert event.event_type == "ip_banned"
    assert event.ip_address == IDENTITY
    assert event.reason == "rate_limit_exceeded"


async def test_the_prefix_length_decides_the_identity_a_ban_covers() -> None:
    manager = _manager(ipv6_prefix_length=56)

    await manager.ban_ip("2001:db8:0:100::/56", 600, "t", grouped=True)

    assert await manager.is_ip_banned("2001:db8:0:1ff::1") is True
    assert await manager.is_ip_banned("2001:db8:0:200::1") is False


async def test_a_ban_at_prefix_length_128_is_per_address() -> None:
    manager = _manager(ipv6_prefix_length=128)

    await manager.ban_ip(HOST, 600, "t")

    assert await manager.is_ip_banned(HOST) is True
    assert await manager.is_ip_banned("2001:db8:0:1::6") is False


async def test_a_6to4_address_is_banned_with_its_slash_48() -> None:
    manager = _manager()
    identity = _client_identity("2002:c000:204::1", 64)

    await manager.ban_ip(identity, 600, "t", grouped=True)

    assert identity == "2002:c000:204::/48"
    assert await manager.is_ip_banned("2002:c000:204:9::7") is True
    assert await manager.is_ip_banned("2002:c000:205::1") is False


async def test_unbanning_an_address_clears_the_identity_it_resolves_to() -> None:
    manager = _manager()
    await manager.ban_ip(IDENTITY, 600, "t", grouped=True)
    await manager.ban_ip(HOST, 600, "t")

    await manager.unban_ip(HOST)

    assert await manager.is_ip_banned(HOST) is False
    assert await manager.is_ip_banned("2001:db8:0:1::77") is False


async def test_unbanning_the_identity_text_clears_it() -> None:
    manager = _manager()
    await manager.ban_ip(IDENTITY, 600, "t", grouped=True)

    await manager.unban_ip(IDENTITY)

    assert await manager.is_ip_banned(HOST) is False


async def test_a_banned_identity_clears_its_strikes_when_unbanned_by_a_range() -> None:
    manager = _manager()
    await manager.ban_ip(IDENTITY, 600, "t", grouped=True)
    forget = AsyncMock()

    with patch.object(manager, "_forget_strikes", forget):
        await manager.unban_inside(["2001:db8::/48"])

    assert await manager.is_ip_banned(HOST) is False
    forget.assert_awaited_once_with(IDENTITY)


async def test_a_range_whitelist_leaves_a_wider_identity_alone() -> None:
    manager = _manager()
    await manager.ban_ip(IDENTITY, 600, "t", grouped=True)

    await manager.unban_inside(["2001:db8:0:1:0:0:0:0/72"])

    assert await manager.is_ip_banned(HOST) is True


async def test_reset_clears_grouped_bans() -> None:
    manager = _manager()
    await manager.ban_ip(IDENTITY, 600, "t", grouped=True)

    await manager.reset()

    assert await manager.is_ip_banned(HOST) is False


def test_a_strike_key_that_is_not_an_address_is_never_inside_a_range() -> None:
    inside = _strike_key_inside(
        NetworkCoverage([ipaddress.ip_network("10.0.0.0/8")]),
        "wp6:rate_limit:violations:",
    )

    assert inside("wp6:rate_limit:violations:malformed-xff@10.0.0.5") is False
    assert inside("wp6:rate_limit:violations:10.1.2.3") is True


async def test_redis_holds_a_grouped_ban_in_its_own_namespace(
    live_redis: RedisManager,
) -> None:
    manager = _manager()
    manager.redis_handler = live_redis

    await manager.ban_ip(IDENTITY, 600, "t", grouped=True)

    assert await live_redis.get_key("banned_identities", IDENTITY)
    assert not await live_redis.keys("banned_networks:*")
    assert not await live_redis.keys("banned_ips:*")


async def test_another_worker_sees_a_grouped_ban_through_redis(
    live_redis: RedisManager,
) -> None:
    writer = _manager()
    writer.redis_handler = live_redis
    await writer.ban_ip(IDENTITY, 600, "t", grouped=True)
    IPBanManager._instance = None
    reader = _manager()
    reader.redis_handler = live_redis

    assert await reader.is_ip_banned(HOST) is True
    assert await reader.is_ip_banned(NEIGHBOUR_HOST) is False


async def test_a_ban_written_by_a_4_4_0_worker_under_the_full_address_still_matches(
    live_redis: RedisManager,
) -> None:
    await live_redis.set_key("banned_ips", HOST, str(time.time() + 600), ttl=600)
    manager = _manager()
    manager.redis_handler = live_redis

    assert await manager.is_ip_banned(HOST) is True
    assert await manager.is_ip_banned("2001:db8:0:1::6") is False


async def test_a_clean_ipv6_request_costs_one_redis_command(
    live_redis: RedisManager,
) -> None:
    manager = _manager()
    manager.redis_handler = live_redis
    await manager.is_ip_banned("2001:db8:0:8::1")
    async with live_redis.get_connection() as conn:
        before = (
            (await conn.info("commandstats")).get("cmdstat_mget", {}).get("calls", 0)
        )
        before_get = (
            (await conn.info("commandstats")).get("cmdstat_get", {}).get("calls", 0)
        )

    await manager.is_ip_banned("2001:db8:0:9::1")

    async with live_redis.get_connection() as conn:
        stats = await conn.info("commandstats")
    assert stats.get("cmdstat_mget", {}).get("calls", 0) - before == 1
    assert stats.get("cmdstat_get", {}).get("calls", 0) - before_get == 0


async def test_reset_unlinks_the_redis_identity_namespace(
    live_redis: RedisManager,
) -> None:
    manager = _manager()
    manager.redis_handler = live_redis
    await manager.ban_ip(IDENTITY, 600, "t", grouped=True)

    await manager.reset()

    assert not await live_redis.keys("banned_identities:*")


async def test_unban_removes_the_redis_identity_key_and_the_exact_key(
    live_redis: RedisManager,
) -> None:
    manager = _manager()
    manager.redis_handler = live_redis
    await manager.ban_ip(IDENTITY, 600, "t", grouped=True)
    await live_redis.set_key("banned_ips", HOST, str(time.time() + 600), ttl=600)

    await manager.unban_ip(HOST)

    assert not await live_redis.keys("banned_identities:*")
    assert not await live_redis.keys("banned_ips:*")
