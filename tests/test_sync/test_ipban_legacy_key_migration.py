import logging
import warnings
from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from guard_core.sync.handlers.redis_handler import (
    redis_handler as redis_handler_factory,
)
from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol

LEGACY_MAPPED_FORM = "::ffff:203.0.113.5"
CANONICAL_FORM = "203.0.113.5"


class _NotAnIterator:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _BadScanConn:
    def __init__(self) -> None:
        self.scan_result = _NotAnIterator()

    def scan_iter(self, match: str | None = None) -> _NotAnIterator:
        return self.scan_result


class _BadScanConnCM:
    def __init__(self, conn: _BadScanConn) -> None:
        self._conn = conn

    def __enter__(self) -> _BadScanConn:
        return self._conn

    def __exit__(self, *args: object) -> None:
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
    handler.connection_cm = _NotAnIterator()
    handler.get_connection.return_value = handler.connection_cm
    return handler


def _seed_legacy_ban(handler: SyncRedisHandlerProtocol, duration: int = 60) -> None:
    ip_ban_manager.initialize_redis(handler)
    ip_ban_manager._ban_exact_ip(LEGACY_MAPPED_FORM, duration, "test_legacy_ban")
    ip_ban_manager.banned_ips.clear()


def test_migration_blocks_canonical_request_after_restart(
    security_config_redis: SyncSecurityConfig,
) -> None:
    handler = redis_handler_factory(security_config_redis)
    handler.initialize()
    try:
        _seed_legacy_ban(handler)

        ip_ban_manager.initialize_redis(handler)
        ip_ban_manager.banned_ips.clear()

        assert ip_ban_manager.is_ip_banned(CANONICAL_FORM) is True
    finally:
        ip_ban_manager.unban_ip(CANONICAL_FORM)
        ip_ban_manager.redis_handler = None
        handler.close()


def test_migration_preserves_remaining_ttl_within_one_second(
    security_config_redis: SyncSecurityConfig,
) -> None:
    handler = redis_handler_factory(security_config_redis)
    handler.initialize()
    try:
        _seed_legacy_ban(handler, duration=60)

        ip_ban_manager.initialize_redis(handler)

        prefix = security_config_redis.redis_prefix
        with handler.get_connection() as conn:
            pttl_ms = conn.pttl(f"{prefix}banned_ips:{CANONICAL_FORM}")

        assert pttl_ms == pytest.approx(60_000, abs=1_000)
    finally:
        ip_ban_manager.unban_ip(CANONICAL_FORM)
        ip_ban_manager.redis_handler = None
        handler.close()


def test_migration_deletes_the_legacy_key(
    security_config_redis: SyncSecurityConfig,
) -> None:
    handler = redis_handler_factory(security_config_redis)
    handler.initialize()
    try:
        _seed_legacy_ban(handler)

        ip_ban_manager.initialize_redis(handler)

        legacy_value = handler.get_key("banned_ips", LEGACY_MAPPED_FORM)
        assert legacy_value is None
    finally:
        ip_ban_manager.unban_ip(CANONICAL_FORM)
        ip_ban_manager.redis_handler = None
        handler.close()


def test_migration_second_start_is_idempotent(
    security_config_redis: SyncSecurityConfig,
) -> None:
    handler = redis_handler_factory(security_config_redis)
    handler.initialize()
    try:
        _seed_legacy_ban(handler)

        ip_ban_manager.initialize_redis(handler)

        prefix = security_config_redis.redis_prefix
        canonical_key = f"{prefix}banned_ips:{CANONICAL_FORM}"
        with handler.get_connection() as conn:
            value_before = conn.get(canonical_key)
            pttl_before = conn.pttl(canonical_key)

        ip_ban_manager.initialize_redis(handler)

        with handler.get_connection() as conn:
            value_after = conn.get(canonical_key)
            pttl_after = conn.pttl(canonical_key)

        assert value_after == value_before
        assert pttl_after == pytest.approx(pttl_before, abs=1_000)
        assert ip_ban_manager.is_ip_banned(CANONICAL_FORM) is True
    finally:
        ip_ban_manager.unban_ip(CANONICAL_FORM)
        ip_ban_manager.redis_handler = None
        handler.close()


def test_rate_limit_keys_stay_unmigrated_self_expire_within_60s(
    security_config_redis: SyncSecurityConfig,
) -> None:
    handler = redis_handler_factory(security_config_redis)
    handler.initialize()
    try:
        handler.set_key("rate_limit", f"rate:{LEGACY_MAPPED_FORM}", "1", ttl=60)

        ip_ban_manager.initialize_redis(handler)

        legacy_value = handler.get_key("rate_limit", f"rate:{LEGACY_MAPPED_FORM}")
        canonical_value = handler.get_key("rate_limit", f"rate:{CANONICAL_FORM}")
        assert legacy_value == "1"
        assert canonical_value is None
    finally:
        handler.delete("rate_limit", f"rate:{LEGACY_MAPPED_FORM}")
        ip_ban_manager.redis_handler = None
        handler.close()


def test_migration_skipped_when_redis_handler_is_none() -> None:
    ip_ban_manager.initialize_redis(None)

    assert ip_ban_manager.redis_handler is None


def test_migration_warns_and_continues_when_connection_fails(
    security_config_redis: SyncSecurityConfig,
    caplog: pytest.LogCaptureFixture,
) -> None:
    handler = redis_handler_factory(security_config_redis)
    handler.initialize()
    handler.close()

    caplog.set_level(logging.WARNING, logger="guard_core.sync.handlers.ipban")
    ip_ban_manager.initialize_redis(handler)

    assert any("Legacy ban-key migration skipped" in r.message for r in caplog.records)
    ip_ban_manager.redis_handler = None


def test_migration_deletes_a_persistent_legacy_key_without_ttl(
    security_config_redis: SyncSecurityConfig,
) -> None:
    handler = redis_handler_factory(security_config_redis)
    handler.initialize()
    try:
        prefix = security_config_redis.redis_prefix
        legacy_key = f"{prefix}banned_ips:{LEGACY_MAPPED_FORM}"
        with handler.get_connection() as conn:
            conn.set(legacy_key, "123456789.0")

        ip_ban_manager.initialize_redis(handler)

        with handler.get_connection() as conn:
            assert conn.exists(legacy_key) == 0
        assert ip_ban_manager.is_ip_banned(CANONICAL_FORM) is False
    finally:
        ip_ban_manager.redis_handler = None
        handler.close()


def test_migration_keeps_the_longer_expiry_when_canonical_key_already_exists(
    security_config_redis: SyncSecurityConfig,
) -> None:
    handler = redis_handler_factory(security_config_redis)
    handler.initialize()
    try:
        ip_ban_manager.initialize_redis(handler)
        ip_ban_manager.ban_ip(CANONICAL_FORM, 120, "test_long_canonical_ban")
        ip_ban_manager._ban_exact_ip(LEGACY_MAPPED_FORM, 60, "test_short_legacy_ban")
        ip_ban_manager.banned_ips.clear()

        prefix = security_config_redis.redis_prefix
        canonical_key = f"{prefix}banned_ips:{CANONICAL_FORM}"
        legacy_key = f"{prefix}banned_ips:{LEGACY_MAPPED_FORM}"
        with handler.get_connection() as conn:
            pttl_before = conn.pttl(canonical_key)

        ip_ban_manager.initialize_redis(handler)

        with handler.get_connection() as conn:
            pttl_after = conn.pttl(canonical_key)
            legacy_exists = conn.exists(legacy_key)

        assert pttl_after == pytest.approx(pttl_before, abs=1_000)
        assert pttl_after > 100_000
        assert legacy_exists == 0
    finally:
        ip_ban_manager.unban_ip(CANONICAL_FORM)
        ip_ban_manager.redis_handler = None
        handler.close()


def test_migration_closes_and_skips_non_async_iterable_scan_result(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="guard_core.sync.handlers.ipban")
    handler = _bad_scan_redis_handler()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            ip_ban_manager.initialize_redis(handler)

        assert handler.conn.scan_result.closed is True
        assert any(
            "Legacy ban-key migration skipped" in r.message for r in caplog.records
        )
    finally:
        ip_ban_manager.redis_handler = None


def test_migration_closes_and_skips_non_async_context_manager_connection(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="guard_core.sync.handlers.ipban")
    handler = _bad_connection_redis_handler()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            ip_ban_manager.initialize_redis(handler)

        assert handler.connection_cm.closed is True
        assert any("redis connection unavailable" in r.message for r in caplog.records)
    finally:
        ip_ban_manager.redis_handler = None
