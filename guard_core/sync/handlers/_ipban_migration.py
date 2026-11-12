import contextlib
import logging
from typing import TYPE_CHECKING

from guard_core.sync._utils.nat64 import nat64_table_of
from guard_core.sync.handlers._ipban_prefix_contract import (
    enforce_prefix_length_contract,
)
from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol
from guard_core.sync.utils import _canonicalize_ip

if TYPE_CHECKING:
    from redis import Redis

    from guard_core.models import SyncSecurityConfig

_BANNED_IPS_NAMESPACE = "banned_ips"
_MISSING_KEY = -2


def _close_if_unusable(obj: object, required_attr: str) -> bool:
    if hasattr(obj, required_attr):
        return True
    close = getattr(obj, "close", None)
    if callable(close):
        with contextlib.suppress(AttributeError):
            close()
    return False


def _expiry_ms(redis_time: tuple[int, int], pttl_ms: int) -> int:
    seconds, microseconds = redis_time
    return seconds * 1_000 + microseconds // 1_000 + pttl_ms


class IpBanMigrationMixin:
    logger: logging.Logger
    redis_handler: SyncRedisHandlerProtocol | None = None
    config: "SyncSecurityConfig | None" = None
    _instance: object

    def initialize_redis(self, redis_handler: SyncRedisHandlerProtocol | None) -> None:
        self.redis_handler = redis_handler
        self._migrate_legacy_ban_keys()
        config = self.config
        if redis_handler is not None and config is not None:
            enforce_prefix_length_contract(redis_handler, config, self.logger)

    def _migrate_legacy_ban_keys(self) -> None:
        if self.redis_handler is None:
            return
        prefix = f"{self.redis_handler.config.redis_prefix}{_BANNED_IPS_NAMESPACE}:"
        connection_cm = self.redis_handler.get_connection()
        if not _close_if_unusable(connection_cm, "__enter__"):
            self.logger.warning(
                "Legacy ban-key migration skipped: redis connection unavailable"
            )
            return
        try:
            with connection_cm as conn:
                scan_result = conn.scan_iter(match=f"{prefix}*")
                if not _close_if_unusable(scan_result, "__iter__"):
                    raise TypeError("redis connection did not return an async iterator")
                for key in scan_result:
                    self._migrate_one_ban_key(conn, key, prefix)
        except Exception as e:
            self.logger.warning("Legacy ban-key migration skipped: %s", e)

    def _migrate_one_ban_key(self, conn: "Redis", key: str, prefix: str) -> None:
        raw_ip = key[len(prefix) :]
        canonical_ip = _canonicalize_ip(raw_ip, nat64_table_of(self.config))
        if canonical_ip == raw_ip:
            return

        with conn.pipeline() as pipe:
            pipe.get(key)
            pipe.pttl(key)
            pipe.time()
            value, old_pttl, old_time = pipe.execute()

        if old_pttl <= 0:
            conn.delete(key)
            return

        expires_at_ms = _expiry_ms(old_time, old_pttl)
        canonical_key = f"{prefix}{canonical_ip}"
        with conn.pipeline() as pipe:
            pipe.pttl(canonical_key)
            pipe.time()
            new_pttl, new_time = pipe.execute()

        if new_pttl == _MISSING_KEY or (
            new_pttl >= 0 and _expiry_ms(new_time, new_pttl) < expires_at_ms
        ):
            with conn.pipeline(transaction=True) as pipe:
                pipe.set(canonical_key, value)
                pipe.pexpireat(canonical_key, expires_at_ms)
                pipe.execute()
        conn.delete(key)
