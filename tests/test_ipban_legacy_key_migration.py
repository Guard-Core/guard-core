import logging
import time
import warnings
from unittest.mock import MagicMock

import pytest

from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.handlers.redis_handler import redis_handler as redis_handler_factory
from guard_core.models import SecurityConfig
from guard_core.protocols.redis_protocol import RedisHandlerProtocol

LEGACY_MAPPED_FORM = "::ffff:203.0.113.5"
CANONICAL_FORM = "203.0.113.5"


class _NotAnAsyncIterator:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _BadScanConn:
    def __init__(self) -> None:
        self.scan_result = _NotAnAsyncIterator()

    def scan_iter(self, match: str | None = None) -> _NotAnAsyncIterator:
        return self.scan_result


class _BadScanConnCM:
    def __init__(self, conn: _BadScanConn) -> None:
        self._conn = conn

    async def __aenter__(self) -> _BadScanConn:
        return self._conn

    async def __aexit__(self, *args: object) -> None:
        return None


def _bad_scan_redis_handler() -> MagicMock:
    handler = MagicMock()
    handler.config.redis_prefix = "test:bad-scan:"
    handler.conn = _BadScanConn()
    handler.get_connection.return_value = _BadScanConnCM(handler.conn)
    return handler


def _bad_connection_redis_handler() -> MagicMock:
    handler = MagicMock()
    handler.config.redis_prefix = "test:bad-connection:"
    handler.connection_cm = _NotAnAsyncIterator()
    handler.get_connection.return_value = handler.connection_cm
    return handler


def _elapsed_ms(since: float) -> float:
    return (time.monotonic() - since) * 1_000


async def _seed_legacy_ban(handler: RedisHandlerProtocol, duration: int = 60) -> None:
    await ip_ban_manager.initialize_redis(handler)
    await ip_ban_manager._ban_exact_ip(LEGACY_MAPPED_FORM, duration, "test_legacy_ban")
    ip_ban_manager.banned_ips.clear()


async def test_migration_blocks_canonical_request_after_restart(
    security_config_redis: SecurityConfig,
) -> None:
    handler = redis_handler_factory(security_config_redis)
    await handler.initialize()
    try:
        await _seed_legacy_ban(handler)

        await ip_ban_manager.initialize_redis(handler)
        ip_ban_manager.banned_ips.clear()

        assert await ip_ban_manager.is_ip_banned(CANONICAL_FORM) is True
    finally:
        await ip_ban_manager.unban_ip(CANONICAL_FORM)
        ip_ban_manager.redis_handler = None
        await handler.close()


async def test_migration_preserves_remaining_ttl_within_one_second(
    security_config_redis: SecurityConfig,
) -> None:
    handler = redis_handler_factory(security_config_redis)
    await handler.initialize()
    try:
        seeded_at = time.monotonic()
        await _seed_legacy_ban(handler, duration=60)

        await ip_ban_manager.initialize_redis(handler)

        prefix = security_config_redis.redis_prefix
        async with handler.get_connection() as conn:
            pttl_ms = await conn.pttl(f"{prefix}banned_ips:{CANONICAL_FORM}")
        elapsed_ms = _elapsed_ms(seeded_at)

        assert 60_000 - elapsed_ms - 1_000 <= pttl_ms <= 60_000 + 1_000
    finally:
        await ip_ban_manager.unban_ip(CANONICAL_FORM)
        ip_ban_manager.redis_handler = None
        await handler.close()


async def test_migration_does_not_extend_the_ban_by_time_lost_mid_migration(
    security_config_redis: SecurityConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handler = redis_handler_factory(security_config_redis)
    await handler.initialize()
    try:
        await _seed_legacy_ban(handler, duration=60)
        async with handler.get_connection() as conn:
            client_type = type(conn)
        read_pttl = client_type.pttl

        async def pttl_then_stall(self: object, key: str) -> int:
            remaining: int = await read_pttl(self, key)
            if type(self) is client_type:
                time.sleep(1.5)
            return remaining

        monkeypatch.setattr(client_type, "pttl", pttl_then_stall)
        await ip_ban_manager.initialize_redis(handler)
        monkeypatch.undo()

        prefix = security_config_redis.redis_prefix
        async with handler.get_connection() as conn:
            pttl_ms = await conn.pttl(f"{prefix}banned_ips:{CANONICAL_FORM}")

        assert pttl_ms <= 60_000 - 1_400
    finally:
        monkeypatch.undo()
        await ip_ban_manager.unban_ip(CANONICAL_FORM)
        ip_ban_manager.redis_handler = None
        await handler.close()


async def test_migration_deletes_the_legacy_key(
    security_config_redis: SecurityConfig,
) -> None:
    handler = redis_handler_factory(security_config_redis)
    await handler.initialize()
    try:
        await _seed_legacy_ban(handler)

        await ip_ban_manager.initialize_redis(handler)

        legacy_value = await handler.get_key("banned_ips", LEGACY_MAPPED_FORM)
        assert legacy_value is None
    finally:
        await ip_ban_manager.unban_ip(CANONICAL_FORM)
        ip_ban_manager.redis_handler = None
        await handler.close()


async def test_migration_second_start_is_idempotent(
    security_config_redis: SecurityConfig,
) -> None:
    handler = redis_handler_factory(security_config_redis)
    await handler.initialize()
    try:
        await _seed_legacy_ban(handler)

        await ip_ban_manager.initialize_redis(handler)

        prefix = security_config_redis.redis_prefix
        canonical_key = f"{prefix}banned_ips:{CANONICAL_FORM}"
        async with handler.get_connection() as conn:
            value_before = await conn.get(canonical_key)
            pttl_before = await conn.pttl(canonical_key)
        read_before_at = time.monotonic()

        await ip_ban_manager.initialize_redis(handler)

        async with handler.get_connection() as conn:
            value_after = await conn.get(canonical_key)
            pttl_after = await conn.pttl(canonical_key)
        elapsed_ms = _elapsed_ms(read_before_at)

        assert value_after == value_before
        assert pttl_before - elapsed_ms - 1_000 <= pttl_after <= pttl_before
        assert await ip_ban_manager.is_ip_banned(CANONICAL_FORM) is True
    finally:
        await ip_ban_manager.unban_ip(CANONICAL_FORM)
        ip_ban_manager.redis_handler = None
        await handler.close()


async def test_rate_limit_keys_stay_unmigrated_self_expire_within_60s(
    security_config_redis: SecurityConfig,
) -> None:
    handler = redis_handler_factory(security_config_redis)
    await handler.initialize()
    try:
        await handler.set_key("rate_limit", f"rate:{LEGACY_MAPPED_FORM}", "1", ttl=60)

        await ip_ban_manager.initialize_redis(handler)

        legacy_value = await handler.get_key("rate_limit", f"rate:{LEGACY_MAPPED_FORM}")
        canonical_value = await handler.get_key("rate_limit", f"rate:{CANONICAL_FORM}")
        assert legacy_value == "1"
        assert canonical_value is None
    finally:
        await handler.delete("rate_limit", f"rate:{LEGACY_MAPPED_FORM}")
        ip_ban_manager.redis_handler = None
        await handler.close()


async def test_migration_skipped_when_redis_handler_is_none() -> None:
    await ip_ban_manager.initialize_redis(None)

    assert ip_ban_manager.redis_handler is None


async def test_migration_warns_and_continues_when_connection_fails(
    security_config_redis: SecurityConfig,
    caplog: pytest.LogCaptureFixture,
) -> None:
    handler = redis_handler_factory(security_config_redis)
    await handler.initialize()
    await handler.close()

    caplog.set_level(logging.WARNING, logger="guard_core.handlers.ipban")
    await ip_ban_manager.initialize_redis(handler)

    assert any("Legacy ban-key migration skipped" in r.message for r in caplog.records)
    ip_ban_manager.redis_handler = None


async def test_migration_deletes_a_persistent_legacy_key_without_ttl(
    security_config_redis: SecurityConfig,
) -> None:
    handler = redis_handler_factory(security_config_redis)
    await handler.initialize()
    try:
        prefix = security_config_redis.redis_prefix
        legacy_key = f"{prefix}banned_ips:{LEGACY_MAPPED_FORM}"
        async with handler.get_connection() as conn:
            await conn.set(legacy_key, "123456789.0")

        await ip_ban_manager.initialize_redis(handler)

        async with handler.get_connection() as conn:
            assert await conn.exists(legacy_key) == 0
        assert await ip_ban_manager.is_ip_banned(CANONICAL_FORM) is False
    finally:
        ip_ban_manager.redis_handler = None
        await handler.close()


async def test_migration_keeps_the_longer_expiry_when_canonical_key_already_exists(
    security_config_redis: SecurityConfig,
) -> None:
    handler = redis_handler_factory(security_config_redis)
    await handler.initialize()
    try:
        await ip_ban_manager.initialize_redis(handler)
        await ip_ban_manager.ban_ip(CANONICAL_FORM, 120, "test_long_canonical_ban")
        await ip_ban_manager._ban_exact_ip(
            LEGACY_MAPPED_FORM, 60, "test_short_legacy_ban"
        )
        ip_ban_manager.banned_ips.clear()

        prefix = security_config_redis.redis_prefix
        canonical_key = f"{prefix}banned_ips:{CANONICAL_FORM}"
        legacy_key = f"{prefix}banned_ips:{LEGACY_MAPPED_FORM}"
        async with handler.get_connection() as conn:
            pttl_before = await conn.pttl(canonical_key)
        read_before_at = time.monotonic()

        await ip_ban_manager.initialize_redis(handler)

        async with handler.get_connection() as conn:
            pttl_after = await conn.pttl(canonical_key)
            legacy_exists = await conn.exists(legacy_key)
        elapsed_ms = _elapsed_ms(read_before_at)

        assert pttl_before - elapsed_ms - 1_000 <= pttl_after <= pttl_before
        assert pttl_after > 100_000
        assert legacy_exists == 0
    finally:
        await ip_ban_manager.unban_ip(CANONICAL_FORM)
        ip_ban_manager.redis_handler = None
        await handler.close()


async def test_migration_closes_and_skips_non_async_iterable_scan_result(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="guard_core.handlers.ipban")
    handler = _bad_scan_redis_handler()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            await ip_ban_manager.initialize_redis(handler)

        assert handler.conn.scan_result.closed is True
        assert any(
            "Legacy ban-key migration skipped" in r.message for r in caplog.records
        )
    finally:
        ip_ban_manager.redis_handler = None


async def test_migration_closes_and_skips_non_async_context_manager_connection(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="guard_core.handlers.ipban")
    handler = _bad_connection_redis_handler()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            await ip_ban_manager.initialize_redis(handler)

        assert handler.connection_cm.closed is True
        assert any("redis connection unavailable" in r.message for r in caplog.records)
    finally:
        ip_ban_manager.redis_handler = None
