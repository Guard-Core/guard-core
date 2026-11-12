import logging
import time
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


def _elapsed_ms(since: float) -> float:
    return (time.monotonic() - since) * 1_000


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
        seeded_at = time.monotonic()
        _seed_legacy_ban(handler, duration=60)

        ip_ban_manager.initialize_redis(handler)

        prefix = security_config_redis.redis_prefix
        with handler.get_connection() as conn:
            pttl_ms = conn.pttl(f"{prefix}banned_ips:{CANONICAL_FORM}")
        elapsed_ms = _elapsed_ms(seeded_at)

        assert 60_000 - elapsed_ms - 1_000 <= pttl_ms <= 60_000 + 1_000
    finally:
        ip_ban_manager.unban_ip(CANONICAL_FORM)
        ip_ban_manager.redis_handler = None
        handler.close()


def test_migration_does_not_extend_the_ban_by_time_lost_mid_migration(
    security_config_redis: SyncSecurityConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handler = redis_handler_factory(security_config_redis)
    handler.initialize()
    try:
        _seed_legacy_ban(handler, duration=60)
        with handler.get_connection() as conn:
            with conn.pipeline() as pipe:
                pipeline_type = type(pipe)
        real_execute = pipeline_type.execute

        def execute_then_stall_after_canonical_read(
            self: object, *args: object, **kw: object
        ) -> object:
            names = [str(c[0][0]).upper() for c in vars(self)["command_stack"]]
            result = real_execute(self, *args, **kw)
            if names == ["PTTL", "TIME"]:
                time.sleep(1.5)
            return result

        monkeypatch.setattr(
            pipeline_type, "execute", execute_then_stall_after_canonical_read
        )
        ip_ban_manager.initialize_redis(handler)
        monkeypatch.undo()

        prefix = security_config_redis.redis_prefix
        with handler.get_connection() as conn:
            pttl_ms = conn.pttl(f"{prefix}banned_ips:{CANONICAL_FORM}")

        assert pttl_ms <= 60_000 - 1_400
    finally:
        monkeypatch.undo()
        ip_ban_manager.unban_ip(CANONICAL_FORM)
        ip_ban_manager.redis_handler = None
        handler.close()


def test_migration_writes_the_canonical_key_and_its_expiry_in_one_transaction(
    security_config_redis: SyncSecurityConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handler = redis_handler_factory(security_config_redis)
    handler.initialize()
    try:
        _seed_legacy_ban(handler, duration=60)
        with handler.get_connection() as conn:
            with conn.pipeline() as pipe:
                pipeline_type = type(pipe)
        real_execute = pipeline_type.execute
        executed: list[tuple[bool, list[str]]] = []

        def recording_execute(self: object, *args: object, **kw: object) -> object:
            state = vars(self)
            names = [str(c[0][0]).upper() for c in state["command_stack"]]
            executed.append(
                (bool(state.get("is_transaction", state.get("transaction"))), names)
            )
            return real_execute(self, *args, **kw)

        monkeypatch.setattr(pipeline_type, "execute", recording_execute)
        ip_ban_manager.initialize_redis(handler)
        monkeypatch.undo()

        assert (True, ["SET", "PEXPIREAT"]) in executed
        prefix = security_config_redis.redis_prefix
        with handler.get_connection() as conn:
            assert conn.pttl(f"{prefix}banned_ips:{CANONICAL_FORM}") > 0
    finally:
        monkeypatch.undo()
        ip_ban_manager.unban_ip(CANONICAL_FORM)
        ip_ban_manager.redis_handler = None
        handler.close()


def test_migration_keeps_a_persistent_canonical_key_unshortened(
    security_config_redis: SyncSecurityConfig,
) -> None:
    handler = redis_handler_factory(security_config_redis)
    handler.initialize()
    try:
        _seed_legacy_ban(handler)
        prefix = security_config_redis.redis_prefix
        canonical_key = f"{prefix}banned_ips:{CANONICAL_FORM}"
        with handler.get_connection() as conn:
            conn.set(canonical_key, "9999999999.5")

        ip_ban_manager.initialize_redis(handler)

        with handler.get_connection() as conn:
            assert conn.pttl(canonical_key) == -1
            assert conn.get(canonical_key) == "9999999999.5"
            assert conn.exists(f"{prefix}banned_ips:{LEGACY_MAPPED_FORM}") == 0
    finally:
        ip_ban_manager.unban_ip(CANONICAL_FORM)
        ip_ban_manager.redis_handler = None
        handler.close()


def test_migration_leaves_no_canonical_key_for_a_ban_that_expired_mid_migration(
    security_config_redis: SyncSecurityConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handler = redis_handler_factory(security_config_redis)
    handler.initialize()
    try:
        prefix = security_config_redis.redis_prefix
        legacy_key = f"{prefix}banned_ips:{LEGACY_MAPPED_FORM}"
        with handler.get_connection() as conn:
            conn.set(legacy_key, "123456789.0", px=400)
            with conn.pipeline() as pipe:
                pipeline_type = type(pipe)
        real_execute = pipeline_type.execute

        def execute_then_outlive_the_ban(
            self: object, *args: object, **kw: object
        ) -> object:
            names = [str(c[0][0]).upper() for c in vars(self)["command_stack"]]
            result = real_execute(self, *args, **kw)
            if names == ["GET", "PTTL", "TIME"]:
                time.sleep(0.8)
            return result

        monkeypatch.setattr(pipeline_type, "execute", execute_then_outlive_the_ban)
        ip_ban_manager.initialize_redis(handler)
        monkeypatch.undo()

        with handler.get_connection() as conn:
            assert conn.exists(f"{prefix}banned_ips:{CANONICAL_FORM}") == 0
            assert conn.exists(legacy_key) == 0
    finally:
        monkeypatch.undo()
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
        read_before_at = time.monotonic()

        ip_ban_manager.initialize_redis(handler)

        with handler.get_connection() as conn:
            value_after = conn.get(canonical_key)
            pttl_after = conn.pttl(canonical_key)
        elapsed_ms = _elapsed_ms(read_before_at)

        assert value_after == value_before
        assert pttl_before - elapsed_ms - 1_000 <= pttl_after <= pttl_before
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
        read_before_at = time.monotonic()

        ip_ban_manager.initialize_redis(handler)

        with handler.get_connection() as conn:
            pttl_after = conn.pttl(canonical_key)
            legacy_exists = conn.exists(legacy_key)
        elapsed_ms = _elapsed_ms(read_before_at)

        assert pttl_before - elapsed_ms - 1_000 <= pttl_after <= pttl_before
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
