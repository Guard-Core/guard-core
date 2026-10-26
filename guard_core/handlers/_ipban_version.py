import ipaddress
import logging
import time
from collections.abc import MutableMapping, Sequence
from typing import TYPE_CHECKING

from guard_core.handlers._ipban_cache import _Network, _OperatorNetworks
from guard_core.protocols.redis_protocol import RedisHandlerProtocol

if TYPE_CHECKING:
    from redis.asyncio import Redis

_VERSION_PAIR = ("ban_version", "counter")
_SCAN_COUNT = 2000
_MGET_BATCH = 1000


class IpBanVersionMixin:
    """Keeps every worker's view of the shared bans current without pub/sub.

    One counter in Redis moves only when something another worker's cache could
    still hold is removed or added out of band: an operator CIDR ban and every
    unban or reset. Auto-bans write their keys only, because every lookup already
    reads the exact keys.
    """

    _VERSION_RECHECK_SECONDS = 1.0
    LOCAL_CACHE_TTL_CAP_SECONDS: int

    banned_ips: MutableMapping[str, float]
    banned_networks: list[tuple[_Network, float]]
    redis_handler: RedisHandlerProtocol | None = None
    logger: logging.Logger
    _ban_version_seen: str | None = None
    _ban_version_checked_at: float = 0.0
    _operator_networks: _OperatorNetworks | None = None

    async def _bump_ban_version(self) -> None:
        if not self.redis_handler:
            return
        try:
            await self.redis_handler.incr(*_VERSION_PAIR)
        except Exception as error:
            self.logger.warning(
                "The ban version could not be advanced, other workers may keep "
                "a lifted or new ban until their next reload: %s",
                error,
            )

    def _local_expiry(self, expiry: float) -> float:
        """What this worker keeps of a ban that Redis also holds: at most
        LOCAL_CACHE_TTL_CAP_SECONDS, so a key removed out of band (a port that
        deletes without moving the version) stops being enforced here within that
        time. A ban held only in memory keeps its full duration."""
        return min(expiry, time.time() + self.LOCAL_CACHE_TTL_CAP_SECONDS)

    async def _write_with_version_bump(
        self,
        redis_handler: RedisHandlerProtocol,
        *,
        sets: Sequence[tuple[str, str, object, int | None]] = (),
        deletes: Sequence[tuple[str, str]] = (),
    ) -> None:
        """The ban writes and the version INCR in one MULTI/EXEC: a worker that
        sees the new version sees the writes, and a failure leaves neither."""
        await redis_handler.write_atomically(
            sets=sets, deletes=deletes, increment=_VERSION_PAIR
        )

    def _version_redis_key(self, redis_handler: RedisHandlerProtocol) -> str:
        prefix = redis_handler.config.redis_prefix
        return f"{prefix}{_VERSION_PAIR[0]}:{_VERSION_PAIR[1]}"

    async def _unlink_with_version_bump(
        self, redis_handler: RedisHandlerProtocol, conn: "Redis", keys: list[str]
    ) -> None:
        async with conn.pipeline(transaction=True) as pipe:
            await pipe.unlink(*keys)
            await pipe.incr(self._version_redis_key(redis_handler))
            await pipe.execute()

    def _forget_shared_state(self) -> None:
        self._operator_networks = None
        self._ban_version_seen = None

    async def _read_operator_expiries(
        self, redis: RedisHandlerProtocol
    ) -> dict[_Network, float]:
        stem = f"{redis.config.redis_prefix}banned_networks:"
        expiries: dict[_Network, float] = {}
        async with redis.get_connection() as conn:
            keys = [
                key async for key in conn.scan_iter(match=f"{stem}*", count=_SCAN_COUNT)
            ]
            for start in range(0, len(keys), _MGET_BATCH):
                batch = keys[start : start + _MGET_BATCH]
                for key, value in zip(batch, await conn.mget(batch), strict=True):
                    try:
                        expiries[
                            ipaddress.ip_network(key[len(stem) :], strict=False)
                        ] = float(value)
                    except (TypeError, ValueError):
                        continue
        return expiries

    async def _reload_operator_networks(
        self, redis_handler: RedisHandlerProtocol
    ) -> None:
        raw = await redis_handler.get_key(*_VERSION_PAIR)
        version = "0" if raw is None else str(raw)
        self._operator_networks = _OperatorNetworks(
            await self._read_operator_expiries(redis_handler)
        )
        self._ban_version_seen = version
        self._ban_version_checked_at = time.time()

    def _version_moved(self, raw: object, now: float) -> bool:
        version = "0" if raw is None else str(raw)
        self._ban_version_checked_at = now
        if self._ban_version_seen is None:
            self._ban_version_seen = version
            return False
        if version == self._ban_version_seen:
            return False
        self.banned_ips.clear()
        return True

    async def _adopt_version(
        self, redis_handler: RedisHandlerProtocol, raw: object, now: float
    ) -> bool:
        if not self._version_moved(raw, now):
            return False
        await self._reload_operator_networks(redis_handler)
        return True

    def _version_recheck_due(self, now: float) -> bool:
        return now - self._ban_version_checked_at >= self._VERSION_RECHECK_SECONDS

    async def _positive_survives_recheck(
        self, redis_handler: RedisHandlerProtocol, now: float
    ) -> bool:
        try:
            raw = await redis_handler.get_key(*_VERSION_PAIR)
        except Exception as error:
            self._ban_version_checked_at = now
            self.logger.warning(
                "The ban version could not be read, keeping the cached ban: %s", error
            )
            return True
        return not await self._adopt_version(redis_handler, raw, now)
