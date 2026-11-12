import contextlib
import logging
from typing import TYPE_CHECKING

from guard_core._utils.nat64 import nat64_table_of
from guard_core.handlers._ipban_prefix_contract import enforce_prefix_length_contract
from guard_core.protocols.redis_protocol import RedisHandlerProtocol
from guard_core.utils import _canonicalize_ip

if TYPE_CHECKING:
    from redis.asyncio import Redis

    from guard_core.models import SecurityConfig

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
    redis_handler: RedisHandlerProtocol | None = None
    config: "SecurityConfig | None" = None
    _instance: object

    async def initialize_redis(
        self, redis_handler: RedisHandlerProtocol | None
    ) -> None:
        self.redis_handler = redis_handler
        await self._migrate_legacy_ban_keys()
        config = self.config
        if redis_handler is not None and config is not None:
            await enforce_prefix_length_contract(redis_handler, config, self.logger)

    async def _migrate_legacy_ban_keys(self) -> None:
        if self.redis_handler is None:
            return
        prefix = f"{self.redis_handler.config.redis_prefix}{_BANNED_IPS_NAMESPACE}:"
        connection_cm = self.redis_handler.get_connection()
        if not _close_if_unusable(connection_cm, "__aenter__"):
            self.logger.warning(
                "Legacy ban-key migration skipped: redis connection unavailable"
            )
            return
        try:
            async with connection_cm as conn:
                scan_result = conn.scan_iter(match=f"{prefix}*")
                if not _close_if_unusable(scan_result, "__aiter__"):
                    raise TypeError("redis connection did not return an async iterator")
                async for key in scan_result:
                    await self._migrate_one_ban_key(conn, key, prefix)
        except Exception as e:
            self.logger.warning("Legacy ban-key migration skipped: %s", e)

    async def _migrate_one_ban_key(self, conn: "Redis", key: str, prefix: str) -> None:
        raw_ip = key[len(prefix) :]
        canonical_ip = _canonicalize_ip(raw_ip, nat64_table_of(self.config))
        if canonical_ip == raw_ip:
            return

        async with conn.pipeline() as pipe:
            await pipe.get(key)
            await pipe.pttl(key)
            await pipe.time()
            value, old_pttl, old_time = await pipe.execute()

        if old_pttl <= 0:
            await conn.delete(key)
            return

        expires_at_ms = _expiry_ms(old_time, old_pttl)
        canonical_key = f"{prefix}{canonical_ip}"
        async with conn.pipeline() as pipe:
            await pipe.pttl(canonical_key)
            await pipe.time()
            new_pttl, new_time = await pipe.execute()

        if new_pttl == _MISSING_KEY or (
            new_pttl >= 0 and _expiry_ms(new_time, new_pttl) < expires_at_ms
        ):
            async with conn.pipeline(transaction=True) as pipe:
                await pipe.set(canonical_key, value)
                await pipe.pexpireat(canonical_key, expires_at_ms)
                await pipe.execute()
        await conn.delete(key)
