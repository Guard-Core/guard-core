import contextlib
import logging
from typing import Any

from guard_core.sync.handlers._ipban_prefix_contract import (
    enforce_prefix_length_contract,
)
from guard_core.sync.utils import _canonicalize_ip

_BANNED_IPS_NAMESPACE = "banned_ips"


def _close_if_unusable(obj: Any, required_attr: str) -> bool:
    if hasattr(obj, required_attr):
        return True
    with contextlib.suppress(AttributeError):
        obj.close()
    return False


class IpBanMigrationMixin:
    logger: logging.Logger
    redis_handler: Any = None
    config: Any = None

    def initialize_redis(self, redis_handler: Any) -> None:
        self.redis_handler = redis_handler
        self._migrate_legacy_ban_keys()
        if redis_handler is not None:
            enforce_prefix_length_contract(redis_handler, self.config, self.logger)

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

    def _migrate_one_ban_key(self, conn: Any, key: str, prefix: str) -> None:
        raw_ip = key[len(prefix) :]
        canonical_ip = _canonicalize_ip(raw_ip)
        if canonical_ip == raw_ip:
            return

        with conn.pipeline() as pipe:
            pipe.get(key)
            pipe.pttl(key)
            value, old_pttl = pipe.execute()

        if old_pttl <= 0:
            conn.delete(key)
            return

        canonical_key = f"{prefix}{canonical_ip}"
        new_pttl = conn.pttl(canonical_key)
        if new_pttl < old_pttl:
            conn.set(canonical_key, value, px=old_pttl)
        conn.delete(key)
