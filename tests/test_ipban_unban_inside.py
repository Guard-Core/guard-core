import ipaddress
import time
from collections.abc import AsyncIterator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_PREFIX, REDIS_URL


@pytest.fixture
async def real_redis() -> AsyncIterator[RedisManager]:
    config = SecurityConfig(
        enable_redis=True, redis_url=REDIS_URL, redis_prefix=REDIS_PREFIX
    )
    RedisManager._instance = None
    redis = RedisManager(config)
    await redis.initialize()
    ip_ban_manager.redis_handler = redis
    yield redis
    ip_ban_manager.redis_handler = None
    await redis.close()


async def _seed(redis: RedisManager) -> None:
    expiry = str(time.time() + 600)
    for namespace, member in (
        ("banned_ips", "198.51.100.7"),
        ("banned_ips", "2001:db8::7"),
        ("banned_networks", "198.51.100.128/25"),
        ("banned_networks", "2001:db8:1::/48"),
        ("banned_ips", "203.0.113.9"),
        ("banned_ips", "2001:db9::1"),
        ("banned_networks", "203.0.113.0/24"),
        ("banned_networks", "198.51.0.0/16"),
        ("other_namespace", "198.51.100.7"),
    ):
        assert await redis.set_key(namespace, member, expiry, ttl=600) is True, member


@pytest.mark.asyncio
async def test_unban_inside_removes_only_covered_redis_keys(
    real_redis: RedisManager,
) -> None:
    await _seed(real_redis)
    with patch.object(real_redis, "keys", AsyncMock(side_effect=AssertionError)):
        await ip_ban_manager.unban_inside(["198.51.100.0/24", "2001:db8::/32"])

    gone = [
        ("banned_ips", "198.51.100.7"),
        ("banned_ips", "2001:db8::7"),
        ("banned_networks", "198.51.100.128/25"),
        ("banned_networks", "2001:db8:1::/48"),
    ]
    kept = [
        ("banned_ips", "203.0.113.9"),
        ("banned_ips", "2001:db9::1"),
        ("banned_networks", "203.0.113.0/24"),
        ("banned_networks", "198.51.0.0/16"),
        ("other_namespace", "198.51.100.7"),
    ]
    for namespace, member in gone:
        assert await real_redis.exists(namespace, member) is False, member
    for namespace, member in kept:
        assert await real_redis.exists(namespace, member) is True, member


@pytest.mark.asyncio
async def test_unban_inside_honors_the_redis_prefix(real_redis: RedisManager) -> None:
    await _seed(real_redis)
    foreign = f"{REDIS_PREFIX}other:banned_ips:198.51.100.8"
    async with real_redis.get_connection() as conn:
        await conn.set(foreign, "1", ex=600)
        try:
            await ip_ban_manager.unban_inside(["198.51.100.0/24"])
            assert await conn.exists(foreign) == 1
        finally:
            await conn.delete(foreign)


@pytest.mark.asyncio
async def test_unban_inside_sends_one_event_per_ip_and_network(
    real_redis: RedisManager,
) -> None:
    agent = MagicMock()
    agent.send_event = AsyncMock()
    ip_ban_manager.agent_handler = agent
    try:
        await ip_ban_manager.ban_ip("198.51.100.7", 600, "threshold_exceeded")
        await ip_ban_manager.ban_ip("198.51.100.128/25", 600, "operator")
        agent.send_event.reset_mock()
        await ip_ban_manager.unban_inside(["198.51.100.0/24"])
    finally:
        ip_ban_manager.agent_handler = None

    events = [call.args[0] for call in agent.send_event.call_args_list]
    assert sorted(event.ip_address for event in events) == [
        "198.51.100.128/25",
        "198.51.100.7",
    ]
    assert {event.event_type for event in events} == {"ip_unbanned"}
    assert {event.action_taken for event in events} == {"unbanned"}
    assert {event.reason for event in events} == {"dynamic_rule_whitelist"}


@pytest.mark.asyncio
async def test_unban_inside_in_one_pass_covers_many_ranges_and_batches() -> None:
    expiry = time.time() + 600
    for i in range(5000):
        ip_ban_manager.banned_ips[f"10.{i // 256}.{i % 256}.1"] = expiry
    ip_ban_manager.banned_ips["not-an-ip"] = expiry
    ip_ban_manager.banned_networks.append((ipaddress.ip_network("10.2.0.0/16"), expiry))
    await ip_ban_manager.unban_inside(["10.0.0.0/15", "10.1.0.0/16", "10.3.0.0/16"])

    assert "10.0.5.1" not in ip_ban_manager.banned_ips
    assert "10.1.255.1" not in ip_ban_manager.banned_ips
    assert "10.2.0.1" in ip_ban_manager.banned_ips
    assert "10.3.7.1" not in ip_ban_manager.banned_ips
    assert "10.4.0.1" in ip_ban_manager.banned_ips
    assert ip_ban_manager.banned_ips["not-an-ip"] == expiry
    assert len(ip_ban_manager.banned_networks) == 1


@pytest.mark.asyncio
async def test_unban_inside_with_nothing_to_do_is_a_no_op() -> None:
    await ip_ban_manager.unban_inside([])


@pytest.mark.asyncio
async def test_unban_inside_survives_a_redis_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    redis = MagicMock()
    redis.config = SecurityConfig(enable_redis=True, redis_prefix="x:")
    redis.get_connection = MagicMock(side_effect=RuntimeError("redis down"))
    ip_ban_manager.banned_ips["198.51.100.7"] = time.time() + 600
    with patch.object(ip_ban_manager, "redis_handler", redis):
        await ip_ban_manager.unban_inside(["198.51.100.0/24"])
    assert "198.51.100.7" not in ip_ban_manager.banned_ips
    assert "Redis unban of whitelisted ranges failed" in caplog.text


@pytest.mark.asyncio
async def test_unban_inside_ignores_redis_network_keys_that_are_not_networks(
    real_redis: RedisManager,
) -> None:
    await real_redis.set_key("banned_networks", "not-a-network", "1", ttl=600)
    await ip_ban_manager.unban_inside(["198.51.100.0/24"])
    assert await real_redis.exists("banned_networks", "not-a-network") is True


@pytest.mark.asyncio
async def test_unban_inside_deletes_redis_keys_in_batches_and_keeps_the_rest(
    real_redis: RedisManager,
) -> None:
    expiry = str(time.time() + 600)
    async with real_redis.get_connection() as conn:
        async with conn.pipeline() as pipe:
            for index in range(2100):
                pipe.set(
                    f"{REDIS_PREFIX}banned_ips:10.9.{index // 256}.{index % 256}",
                    expiry,
                    ex=600,
                )
            pipe.set(f"{REDIS_PREFIX}banned_ips:10.10.0.1", expiry, ex=600)
            seeded = await pipe.execute()
    assert seeded == [True] * 2101

    await ip_ban_manager.unban_inside(["10.9.0.0/20"])

    assert await real_redis.exists("banned_ips", "10.9.0.0") is False
    assert await real_redis.exists("banned_ips", "10.9.8.51") is False
    assert await real_redis.exists("banned_ips", "10.10.0.1") is True
    async with real_redis.get_connection() as conn:
        remaining = [
            key async for key in conn.scan_iter(match=f"{REDIS_PREFIX}banned_ips:*")
        ]
    assert remaining == [f"{REDIS_PREFIX}banned_ips:10.10.0.1"]


@pytest.mark.asyncio
async def test_unban_inside_does_not_walk_the_expiry_ordered_cache_iterator() -> None:
    from cachetools import TTLCache

    expiry = time.time() + 600
    for index in range(300):
        ip_ban_manager.banned_ips[f"10.7.0.{index % 250}"] = expiry

    def refuse(self: object) -> None:
        raise AssertionError("TTLCache iteration walks and expires every entry")

    with patch.object(TTLCache, "__iter__", refuse):
        await ip_ban_manager.unban_inside(["10.7.0.0/24"])

    assert len(ip_ban_manager.banned_ips) == 0
