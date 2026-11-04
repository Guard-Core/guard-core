import asyncio
import gc
import warnings
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from redis.asyncio.connection import Connection

from guard_core.exceptions import GeoDatabaseLoadError
from guard_core.handlers.ipinfo_handler import IPInfoManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL, suite_redis_prefix


@pytest.fixture
async def bound_pair(
    tmp_path: Path,
) -> AsyncIterator[tuple[RedisManager, IPInfoManager]]:
    IPInfoManager._instance = None
    config = SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=suite_redis_prefix("wp419close"),
    )
    redis = RedisManager(config)
    await redis.initialize()
    assert redis._redis is not None
    await redis._redis.connection_pool.disconnect()
    geo = IPInfoManager("token", tmp_path / "country_asn.mmdb")
    geo._bind_redis_handler(redis)
    yield redis, geo
    geo._cancel_staleness_timer()
    IPInfoManager._instance = None
    await redis.close()


async def test_closing_redis_stops_a_geo_load_that_is_still_connecting(
    bound_pair: tuple[RedisManager, IPInfoManager], monkeypatch: pytest.MonkeyPatch
) -> None:
    redis, geo = bound_pair
    connecting = asyncio.Event()
    release = asyncio.Event()
    original_connect = Connection.connect

    async def connect_held(self: Connection, *args: object, **kwargs: object) -> None:
        connecting.set()
        await release.wait()
        await original_connect(self)

    monkeypatch.setattr(Connection, "connect", connect_held)
    geo.schedule_database_load()
    await asyncio.wait_for(connecting.wait(), 10)
    task = geo._background_task

    await redis.close()
    release.set()
    if task is not None:
        await asyncio.gather(task, return_exceptions=True)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        gc.collect()
    assert [str(w.message) for w in caught if "unclosed" in str(w.message)] == []


async def test_closing_redis_does_not_cancel_another_request_waiting_for_the_load(
    bound_pair: tuple[RedisManager, IPInfoManager], monkeypatch: pytest.MonkeyPatch
) -> None:
    redis, geo = bound_pair
    connecting = asyncio.Event()
    release = asyncio.Event()
    original_connect = Connection.connect

    async def connect_held(self: Connection, *args: object, **kwargs: object) -> None:
        connecting.set()
        await release.wait()
        await original_connect(self)

    monkeypatch.setattr(Connection, "connect", connect_held)
    waiter = asyncio.create_task(geo.ensure_database_loaded())
    await asyncio.wait_for(connecting.wait(), 10)

    await redis.close()
    release.set()
    outcome = await asyncio.gather(waiter, return_exceptions=True)

    assert not waiter.cancelled()
    assert isinstance(outcome[0], GeoDatabaseLoadError)
