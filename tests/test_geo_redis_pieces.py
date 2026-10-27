import tracemalloc
from pathlib import Path
from typing import Any

import aiohttp
import pytest
import redis as plain_redis
from redis.asyncio import Redis
from redis.asyncio.client import Pipeline

from guard_core.handlers import _ipinfo_redis_copy as copy_module
from guard_core.handlers import _ipinfo_redis_pieces as pieces
from guard_core.handlers.ipinfo_handler import IPInfoManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL
from tests.geo_fixture import (
    CLIENT_IP,
    padded_database_bytes,
    sized_body_server,
)

MIB = 1024 * 1024
BODIES = {
    "zero": b"\x00",
    "ff": b"\xff",
    "every-byte": bytes(range(256)),
}
SMALL_PIECE = 4097
# one 1 MiB piece is alive as bytes, str, UTF-8 and the packed command (6 MiB sync,
# 9 MiB async with the client's read buffers, measured); a body held whole is 24 MiB
# or more here, 3 to 4 copies of it with the old paths
PIECE_PEAK_BOUND = 12 * MIB


@pytest.fixture(autouse=True)
def _reset_singleton() -> Any:
    IPInfoManager._instance = None
    yield
    IPInfoManager._instance = None


async def _handler(config: SecurityConfig) -> RedisManager:
    handler = RedisManager(config)
    await handler.initialize()
    return handler


def _manager(tmp_path: Path, handler: RedisManager, name: str = "geo") -> IPInfoManager:
    IPInfoManager._instance = None
    manager = IPInfoManager(token="tok", db_path=tmp_path / f"{name}.mmdb")
    manager.redis_handler = handler
    manager._max_age = 3600
    return manager


def _final_key(config: SecurityConfig) -> str:
    return f"{config.redis_prefix}ipinfo:database"


async def _all_database_keys(
    handler: RedisManager, config: SecurityConfig
) -> list[str]:
    async with handler.get_connection() as conn:
        return sorted(await conn.keys(f"{config.redis_prefix}ipinfo:*"))


def _sync_client() -> Any:
    return plain_redis.Redis.from_url(REDIS_URL, decode_responses=True)


@pytest.mark.parametrize("padding", list(BODIES))
async def test_the_stored_bytes_equal_the_single_set_of_the_latin_1_text(
    padding: str, security_config_redis: SecurityConfig, tmp_path: Path
) -> None:
    body = padded_database_bytes(BODIES[padding], 300000)
    handler = await _handler(security_config_redis)
    manager = _manager(tmp_path, handler)
    manager.db_path.write_bytes(body)

    await manager._cache_database_in_redis()
    await handler.set_key("ipinfo", "control", body.decode("latin-1"))

    async with handler.get_connection() as conn:
        key = _final_key(security_config_redis)
        control = f"{security_config_redis.redis_prefix}ipinfo:control"
        assert await conn.strlen(key) == await conn.strlen(control)
        assert await conn.get(key) == await conn.get(control)
    database = await handler.get_key("ipinfo", "database")
    assert database is not None
    assert database.encode("latin-1") == body
    await handler.close()


async def test_the_final_key_has_the_max_age_ttl_and_no_temp_key_is_left(
    security_config_redis: SecurityConfig, tmp_path: Path
) -> None:
    handler = await _handler(security_config_redis)
    manager = _manager(tmp_path, handler)
    manager.db_path.write_bytes(padded_database_bytes(b"\xff", 200000))

    await manager._cache_database_in_redis()

    async with handler.get_connection() as conn:
        ttl = await conn.ttl(_final_key(security_config_redis))
    assert 3500 < ttl <= 3600
    assert await _all_database_keys(handler, security_config_redis) == [
        _final_key(security_config_redis)
    ]
    await handler.close()


async def test_a_failed_transfer_leaves_no_partial_key_and_keeps_the_old_value(
    security_config_redis: SecurityConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pieces, "PIECE_BYTES", SMALL_PIECE)
    handler = await _handler(security_config_redis)
    manager = _manager(tmp_path, handler)
    manager.db_path.write_bytes(padded_database_bytes(b"\xff", 200000))
    await handler.set_key("ipinfo", "database", "the old value")
    seen: dict[str, Any] = {"appends": 0, "temp_ttl": None}
    real_append = Redis.append

    async def failing_append(self: Redis, key: str, value: bytes) -> int:
        seen["appends"] += 1
        if seen["appends"] == 3:
            seen["temp_ttl"] = await self.ttl(key)
            raise ConnectionError("the link broke mid transfer")
        return int(await real_append(self, key, value))

    monkeypatch.setattr(Redis, "append", failing_append)
    await manager._cache_database_in_redis()

    assert seen["appends"] == 3
    assert 0 < seen["temp_ttl"] <= manager._download_total_timeout
    assert await handler.get_key("ipinfo", "database") == "the old value"
    assert await _all_database_keys(handler, security_config_redis) == [
        _final_key(security_config_redis)
    ]
    await handler.close()


async def test_two_writers_that_interleave_leave_one_complete_body(
    security_config_redis: SecurityConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pieces, "PIECE_BYTES", SMALL_PIECE)
    handler = await _handler(security_config_redis)
    first = _manager(tmp_path, handler, "first")
    second = _manager(tmp_path, handler, "second")
    body_first = padded_database_bytes(b"\x01", 100000, "CN")
    body_second = padded_database_bytes(b"\xfe", 120000, "US")
    first.db_path.write_bytes(body_first)
    second.db_path.write_bytes(body_second)
    real_append = Redis.append
    running = {"second": False}

    async def interleaving_append(self: Redis, key: str, value: bytes) -> int:
        if not running["second"]:
            running["second"] = True
            await second._cache_database_in_redis()
        return int(await real_append(self, key, value))

    monkeypatch.setattr(Redis, "append", interleaving_append)
    await first._cache_database_in_redis()

    database = await handler.get_key("ipinfo", "database")
    assert database is not None
    stored = database.encode("latin-1")
    assert stored == body_first
    assert await _all_database_keys(handler, security_config_redis) == [
        _final_key(security_config_redis)
    ]
    await handler.close()


async def test_a_database_written_in_pieces_is_adopted_across_odd_piece_boundaries(
    security_config_redis: SecurityConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pieces, "PIECE_BYTES", SMALL_PIECE)
    handler = await _handler(security_config_redis)
    writer = _manager(tmp_path, handler, "writer")
    body = padded_database_bytes(b"\xff", 300000)
    writer.db_path.write_bytes(body)
    await writer._cache_database_in_redis()
    reader = _manager(tmp_path, handler, "reader")

    assert await reader._adopt_redis_copy() is True

    assert reader.db_path.read_bytes() == body
    assert reader.reader is not None
    assert reader.reader.get(CLIENT_IP) is not None
    await handler.close()


async def test_a_rename_during_a_chunked_read_retries_and_adopts_the_new_database(
    security_config_redis: SecurityConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pieces, "PIECE_BYTES", SMALL_PIECE)
    handler = await _handler(security_config_redis)
    old_body = padded_database_bytes(b"\xff", 200000, "CN")
    new_body = padded_database_bytes(b"\x01", 240000, "US")
    key = _final_key(security_config_redis)
    client = _sync_client()
    client.set(key, old_body.decode("latin-1"))
    reader = _manager(tmp_path, handler, "reader")
    swapped = {"done": False, "reads": 0}
    real_command = Pipeline.execute_command

    def swapping_command(self: Pipeline, *args: Any, **kwargs: Any) -> Any:
        if args[0] == "GETRANGE":
            swapped["reads"] += 1
            if not swapped["done"] and swapped["reads"] == 2:
                swapped["done"] = True
                client.set(f"{key}:new", new_body.decode("latin-1"))
                client.rename(f"{key}:new", key)
        return real_command(self, *args, **kwargs)

    monkeypatch.setattr(Pipeline, "execute_command", swapping_command)
    assert await reader._adopt_redis_copy() is True

    assert swapped["done"]
    assert reader.db_path.read_bytes() == new_body
    assert client.exists(key) == 1
    client.close()
    await handler.close()


async def test_a_database_that_keeps_changing_is_not_adopted_and_the_key_survives(
    security_config_redis: SecurityConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pieces, "PIECE_BYTES", SMALL_PIECE)
    handler = await _handler(security_config_redis)
    key = _final_key(security_config_redis)
    client = _sync_client()
    client.set(key, padded_database_bytes(b"\xff", 200000).decode("latin-1"))
    reader = _manager(tmp_path, handler, "reader")
    real_command = Pipeline.execute_command

    def always_changing(self: Pipeline, *args: Any, **kwargs: Any) -> Any:
        if args[0] == "GETRANGE":
            client.set(key, padded_database_bytes(b"\xff", 200000).decode("latin-1"))
        return real_command(self, *args, **kwargs)

    monkeypatch.setattr(Pipeline, "execute_command", always_changing)

    assert await reader._adopt_redis_copy() is False

    assert client.exists(key) == 1
    assert not reader.db_path.with_name("reader.mmdb.tmp").exists()
    client.close()
    await handler.close()


async def test_a_clean_read_of_a_value_that_is_not_a_database_drops_the_key(
    security_config_redis: SecurityConfig, tmp_path: Path
) -> None:
    handler = await _handler(security_config_redis)
    await handler.set_key("ipinfo", "database", "not a database")
    reader = _manager(tmp_path, handler, "reader")

    assert await reader._adopt_redis_copy() is False

    assert await handler.get_key("ipinfo", "database") is None
    await handler.close()


async def test_a_value_that_is_not_latin_1_text_is_dropped(
    security_config_redis: SecurityConfig, tmp_path: Path
) -> None:
    handler = await _handler(security_config_redis)
    await handler.set_key("ipinfo", "database", "beyond latin-1: €")
    reader = _manager(tmp_path, handler, "reader")

    assert await reader._adopt_redis_copy() is False

    assert await handler.get_key("ipinfo", "database") is None
    await handler.close()


async def test_a_value_cut_inside_a_utf8_sequence_is_dropped(
    security_config_redis: SecurityConfig, tmp_path: Path
) -> None:
    handler = await _handler(security_config_redis)
    client = _sync_client()
    client.set(_final_key(security_config_redis), b"abc\xc3")
    reader = _manager(tmp_path, handler, "reader")

    assert await reader._adopt_redis_copy() is False

    assert await handler.get_key("ipinfo", "database") is None
    client.close()
    await handler.close()


async def test_no_cached_database_is_not_adopted(
    security_config_redis: SecurityConfig, tmp_path: Path
) -> None:
    handler = await _handler(security_config_redis)
    reader = _manager(tmp_path, handler, "reader")

    assert await reader._adopt_redis_copy() is False

    assert not reader.db_path.with_name("reader.mmdb.tmp").exists()
    await handler.close()


async def test_a_redis_failure_while_reading_is_a_warning_not_a_drop(
    security_config_redis: SecurityConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handler = await _handler(security_config_redis)
    await handler.set_key("ipinfo", "database", "kept")
    reader = _manager(tmp_path, handler, "reader")

    async def broken(*args: Any, **kwargs: Any) -> bool:
        raise ConnectionError("down")

    monkeypatch.setattr(copy_module, "read_pieces_into_file", broken)

    assert await reader._adopt_redis_copy() is False

    assert await handler.get_key("ipinfo", "database") == "kept"
    await handler.close()


async def test_a_clean_read_of_an_invalid_database_drops_the_key(
    security_config_redis: SecurityConfig, tmp_path: Path
) -> None:
    handler = await _handler(security_config_redis)
    valid = padded_database_bytes(b"\x00", 50000)
    broken = valid[:-30] + b"\x00" * 30
    await handler.set_key("ipinfo", "database", broken.decode("latin-1"))
    reader = _manager(tmp_path, handler, "reader")

    assert await reader._adopt_redis_copy() is False

    assert await handler.get_key("ipinfo", "database") is None
    await handler.close()


async def test_the_download_to_a_file_never_holds_the_body_in_memory(
    tmp_path: Path,
) -> None:
    body = 32 * MIB
    manager = IPInfoManager(token="tok", db_path=tmp_path / "geo.mmdb")
    with sized_body_server(body) as server:
        manager._download_url = server.url
        manager._download_max_bytes = 2 * body
        tracemalloc.start()
        try:
            with open(tmp_path / "raw.bin", "wb") as sink:
                async with aiohttp.ClientSession() as session:
                    await manager._download_body(session, {}, sink)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

    assert (tmp_path / "raw.bin").stat().st_size == body
    assert peak < PIECE_PEAK_BOUND


async def test_storing_and_adopting_a_database_never_holds_it_in_memory(
    security_config_redis: SecurityConfig, tmp_path: Path
) -> None:
    size = 24 * MIB
    handler = await _handler(security_config_redis)
    writer = _manager(tmp_path, handler, "writer")
    writer.db_path.write_bytes(padded_database_bytes(b"\xff", size))
    reader = _manager(tmp_path, handler, "reader")

    tracemalloc.start()
    try:
        await writer._cache_database_in_redis()
        stored_peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.reset_peak()
        assert await reader._adopt_redis_copy() is True
        adopted_peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()

    assert stored_peak < PIECE_PEAK_BOUND
    assert adopted_peak < PIECE_PEAK_BOUND
    await handler.close()


async def test_a_database_that_cannot_be_written_leaves_no_temp_file(
    tmp_path: Path,
) -> None:
    IPInfoManager._instance = None
    manager = IPInfoManager(token="tok", db_path=tmp_path / "missing" / "geo.mmdb")

    with pytest.raises(OSError):
        manager._write_database_atomically(b"x")

    assert not manager._database_tmp_path().exists()
