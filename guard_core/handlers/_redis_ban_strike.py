import hashlib
import os
from collections.abc import Awaitable, Callable, Sequence
from typing import TYPE_CHECKING, Any

from redis.asyncio import Redis

from guard_core.handlers._redis_lean import lean_evalsha
from guard_core.scripts.detection_strikes_lua import (
    BAN_CHECK_AND_RECORD_STRIKE_SCRIPT,
)

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig

_BAN_CHECK_AND_RECORD_STRIKE_SHA = hashlib.sha1(
    BAN_CHECK_AND_RECORD_STRIKE_SCRIPT.encode(), usedforsecurity=False
).hexdigest()


class RedisBanStrikeMixin:
    """The ban lookup and the detection strike of a request, in one round trip."""

    if TYPE_CHECKING:
        config: SecurityConfig

        def _detection_strike_keys(self, client_ip: str) -> tuple[str, str, str]: ...

        def _rate_limit_violations_key(self, client_ip: str) -> str: ...

        async def safe_operation(
            self, func: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any
        ) -> Any: ...

    async def get_bans_and_record_strike(
        self,
        pairs: Sequence[tuple[str, str]],
        version_pair: tuple[str, str],
        seen_version: str | None,
        now: float,
        client_ip: str,
        categories: Sequence[str],
        timestamp: float,
        window_start: float,
        ttl: int,
        cap: int,
    ) -> tuple[list[Any], tuple[int, int, dict[str, int]] | None]:
        """Read the ban keys and the ban version (what ``get_many`` reads for
        ``pairs`` plus ``version_pair``) and, in the same round trip, record one
        detection strike (what ``record_detection_strikes`` records) when none
        of the keys holds a live ban and the version is the one this process
        has seen (``seen_version``, ``None`` when it has seen none).
        ``now`` is the clock the ban expiries are compared with.
        Returns the values read and the strike result, ``None`` when no strike
        was recorded."""
        prefix = self.config.redis_prefix
        index, total, category_prefix = self._detection_strike_keys(client_ip)
        keys = [
            *(f"{prefix}{namespace}:{key}" for namespace, key in pairs),
            f"{prefix}{version_pair[0]}:{version_pair[1]}",
            index,
            total,
            self._rate_limit_violations_key(client_ip),
            *(f"{category_prefix}{name}" for name in categories),
        ]
        arguments = "|".join(
            (
                repr(timestamp),
                os.urandom(16).hex(),
                repr(window_start),
                str(ttl),
                str(cap),
                str(len(pairs)),
                "" if seen_version is None else seen_version,
                repr(now),
            )
        )
        packed_keys = [key.encode() for key in keys]
        packed_arguments = [arguments.encode()]

        async def _get_many(conn: Redis) -> list[Any]:
            reply: list[Any] = await lean_evalsha(
                conn,
                BAN_CHECK_AND_RECORD_STRIKE_SCRIPT,
                _BAN_CHECK_AND_RECORD_STRIKE_SHA,
                packed_keys,
                packed_arguments,
            )
            return reply

        reply = await self.safe_operation(_get_many)
        read = len(pairs) + 1
        status = reply[0]
        if status == 0:
            return reply[1 : read + 1], None
        if status == 1:
            values: list[Any] = [None] * len(pairs)
            values.append(seen_version)
            counts = reply[1:]
        else:
            values = reply[1 : read + 1]
            counts = reply[read + 1 :]
        return values, (
            int(counts[0]),
            int(counts[1]),
            {
                name: int(count)
                for name, count in zip(categories, counts[2:], strict=True)
            },
        )
