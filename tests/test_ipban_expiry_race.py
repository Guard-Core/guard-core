import sys
import time
from collections.abc import Generator, Sequence
from types import ModuleType
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from cachetools import TTLCache
from pydantic import BaseModel, ConfigDict

from guard_core.handlers.ipban_handler import IPBanManager
from tests.fake_agent import redis_slot
from tests.ipban_redis_fake import fake_ban_redis


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


@pytest.fixture(autouse=True)
def fake_guard_agent() -> Generator[None, None, None]:
    module = ModuleType("guard_agent")

    class _SecurityEvent(BaseModel):
        model_config = ConfigDict(extra="allow")

    module.__dict__["SecurityEvent"] = _SecurityEvent
    sys.modules["guard_agent"] = module
    yield
    del sys.modules["guard_agent"]


class _BoundaryTimer:
    def __init__(self, readings: list[float]) -> None:
        self.readings = readings
        self.calls = 0

    def __call__(self) -> float:
        reading = self.readings[min(self.calls, len(self.readings) - 1)]
        self.calls += 1
        return reading


class _RecordingRedisHandler:
    def __init__(self) -> None:
        self.get_key_calls: list[tuple[str, str]] = []
        self.delete_calls: list[tuple[str, str]] = []
        self.expiries: dict[str, str] = {}

    async def get_key(self, namespace: str, key: str) -> str | None:
        self.get_key_calls.append((namespace, key))
        return self.expiries.get(key)

    async def get_many(self, pairs: Sequence[tuple[str, str]]) -> list[str | None]:
        ban_pairs = pairs[:-1]
        for namespace, key in ban_pairs:
            self.get_key_calls.append((namespace, key))
        return [*(self.expiries.get(key) for _, key in ban_pairs), None]

    def get_connection(self) -> Any:
        return fake_ban_redis().get_connection()

    @property
    def config(self) -> Any:
        return MagicMock(redis_prefix="guard:")

    async def delete(self, namespace: str, key: str) -> None:
        self.delete_calls.append((namespace, key))

    async def write_atomically(
        self,
        *,
        sets: Any = (),
        deletes: Any = (),
        increment: Any = None,
    ) -> None:
        self.delete_calls.extend(deletes)

    async def forget_detection_strikes(self, client_ip: str) -> None:
        self.delete_calls.append(("detection_strikes", client_ip))


@pytest.mark.asyncio
async def test_is_ip_banned_live_entry_decided_with_one_cache_clock_read() -> None:
    manager = IPBanManager()
    timer = _BoundaryTimer([0.0, 0.0, 300.0])
    manager.banned_ips = TTLCache(maxsize=10, ttl=300, timer=timer)
    redis = _RecordingRedisHandler()
    manager.redis_handler = redis_slot(redis)

    manager.banned_ips["172.16.10.1"] = time.time() + 60
    manager._ban_version_checked_at = time.time()

    assert await manager.is_ip_banned("172.16.10.1") is True
    assert redis.get_key_calls == []
    assert timer.calls == 2


@pytest.mark.asyncio
async def test_is_ip_banned_expired_at_read_returns_false_without_raising() -> None:
    manager = IPBanManager()
    manager.banned_ips = TTLCache(
        maxsize=10, ttl=300, timer=_BoundaryTimer([0.0, 300.0])
    )
    redis = _RecordingRedisHandler()
    manager.redis_handler = redis_slot(redis)

    manager.banned_ips["172.16.10.2"] = time.time() + 300
    manager._ban_version_checked_at = time.time()

    assert await manager.is_ip_banned("172.16.10.2") is False
    assert ("banned_ips", "172.16.10.2") in redis.get_key_calls


@pytest.mark.asyncio
async def test_is_ip_banned_stale_entry_purged_and_returns_false() -> None:
    manager = IPBanManager()
    manager.redis_handler = None

    manager.banned_ips["172.16.10.3"] = time.time() - 5

    assert await manager.is_ip_banned("172.16.10.3") is False
    assert "172.16.10.3" not in manager.banned_ips


@pytest.mark.asyncio
async def test_unban_survives_expiry_between_membership_check_and_delete() -> None:
    manager = IPBanManager()
    timer = _BoundaryTimer([0.0, 0.0, 300.0])
    manager.banned_ips = TTLCache(maxsize=10, ttl=300, timer=timer)
    redis = _RecordingRedisHandler()
    manager.redis_handler = redis_slot(redis)
    agent = AsyncMock()
    manager.agent_handler = agent

    manager.banned_ips["172.16.10.4"] = time.time() + 300

    await manager.unban_ip("172.16.10.4")

    assert redis.delete_calls == [
        ("banned_ips", "172.16.10.4"),
        ("ban_floors:banned_ips", "172.16.10.4"),
        ("rate_limit", "violations:172.16.10.4"),
        ("detection_strikes", "172.16.10.4"),
        ("recidive", "172.16.10.4"),
    ]
    agent.send_event.assert_awaited_once()


@pytest.mark.asyncio
async def test_unban_expired_entry_is_noop_and_side_effects_still_run() -> None:
    manager = IPBanManager()
    manager.banned_ips = TTLCache(
        maxsize=10, ttl=300, timer=_BoundaryTimer([0.0, 300.0])
    )
    redis = _RecordingRedisHandler()
    manager.redis_handler = redis_slot(redis)
    agent = AsyncMock()
    manager.agent_handler = agent

    manager.banned_ips["172.16.10.5"] = time.time() + 300

    await manager.unban_ip("172.16.10.5")

    assert "172.16.10.5" not in manager.banned_ips
    assert redis.delete_calls == [
        ("banned_ips", "172.16.10.5"),
        ("ban_floors:banned_ips", "172.16.10.5"),
        ("rate_limit", "violations:172.16.10.5"),
        ("detection_strikes", "172.16.10.5"),
        ("recidive", "172.16.10.5"),
    ]
    agent.send_event.assert_awaited_once()
