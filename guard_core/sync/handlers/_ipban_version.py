import ipaddress
import logging
import time
from collections.abc import MutableMapping, Sequence
from typing import Any

from guard_core.sync.handlers._ipban_cache import _Network, _OperatorNetworks

_VERSION_PAIR = ("ban_version", "counter")
_SCAN_COUNT = 2000
_MGET_BATCH = 1000


def _normalize_version(raw: Any) -> str:
    return "0" if raw is None else str(raw)


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
    redis_handler: Any = None
    logger: logging.Logger
    _ban_version_seen: str | None = None
    _ban_version_checked_at: float = 0.0
    _operator_networks: _OperatorNetworks | None = None

    def _bump_ban_version(self) -> None:
        if not self.redis_handler:
            return
        try:
            self.redis_handler.incr(*_VERSION_PAIR)
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

    def _write_with_version_bump(
        self,
        *,
        sets: Sequence[tuple[str, str, Any, int | None]] = (),
        deletes: Sequence[tuple[str, str]] = (),
    ) -> None:
        """The ban writes and the version INCR in one MULTI/EXEC: a worker that
        sees the new version sees the writes, and a failure leaves neither."""
        self.redis_handler.write_atomically(
            sets=sets, deletes=deletes, increment=_VERSION_PAIR
        )

    def _version_redis_key(self) -> str:
        prefix = self.redis_handler.config.redis_prefix
        return f"{prefix}{_VERSION_PAIR[0]}:{_VERSION_PAIR[1]}"

    def _unlink_with_version_bump(self, conn: Any, keys: list[str]) -> None:
        with conn.pipeline(transaction=True) as pipe:
            pipe.unlink(*keys)
            pipe.incr(self._version_redis_key())
            pipe.execute()

    def _forget_shared_state(self) -> None:
        self._operator_networks = None
        self._ban_version_seen = None

    def _read_operator_expiries(self) -> dict[_Network, float]:
        redis = self.redis_handler
        stem = f"{redis.config.redis_prefix}banned_networks:"
        expiries: dict[_Network, float] = {}
        with redis.get_connection() as conn:
            keys = [key for key in conn.scan_iter(match=f"{stem}*", count=_SCAN_COUNT)]
            for start in range(0, len(keys), _MGET_BATCH):
                batch = keys[start : start + _MGET_BATCH]
                for key, value in zip(batch, conn.mget(batch), strict=True):
                    try:
                        expiries[
                            ipaddress.ip_network(key[len(stem) :], strict=False)
                        ] = float(value)
                    except (TypeError, ValueError):
                        continue
        return expiries

    def _reload_operator_networks(self) -> None:
        version = _normalize_version(self.redis_handler.get_key(*_VERSION_PAIR))
        self._operator_networks = _OperatorNetworks(self._read_operator_expiries())
        self._ban_version_seen = version
        self._ban_version_checked_at = time.time()

    def _version_moved(self, raw: Any, now: float) -> bool:
        version = _normalize_version(raw)
        self._ban_version_checked_at = now
        if self._ban_version_seen is None:
            self._ban_version_seen = version
            return False
        if version == self._ban_version_seen:
            return False
        self.banned_ips.clear()
        return True

    def _adopt_version(self, raw: Any, now: float) -> bool:
        if not self._version_moved(raw, now):
            return False
        self._reload_operator_networks()
        return True

    def _version_recheck_due(self, now: float) -> bool:
        return bool(self.redis_handler) and (
            now - self._ban_version_checked_at >= self._VERSION_RECHECK_SECONDS
        )

    def _positive_survives_recheck(self, now: float) -> bool:
        try:
            raw = self.redis_handler.get_key(*_VERSION_PAIR)
        except Exception as error:
            self._ban_version_checked_at = now
            self.logger.warning(
                "The ban version could not be read, keeping the cached ban: %s", error
            )
            return True
        return not self._adopt_version(raw, now)
