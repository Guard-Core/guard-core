"""The Redis rate limiter fallback: record, then count, in one transaction."""

import math
import uuid
from collections.abc import Sequence
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from redis.asyncio import Redis


class _Tier(Protocol):
    @property
    def limit(self) -> int: ...

    @property
    def window(self) -> int: ...


def _retry_after_seconds(oldest: float | None, window: int, now: float) -> int:
    if oldest is None:
        return window
    return max(1, math.ceil(oldest + window - now))


_PIPELINE_COMMANDS_PER_TIER = 5


async def pipeline_blocked_tier(
    conn: "Redis", keys: list[str], tiers: Sequence[_Tier]
) -> tuple[int, int, int] | None:
    seconds, microseconds = await conn.time()
    now = int(seconds) + int(microseconds) / 1_000_000
    member = f"{now}:{uuid.uuid4().hex}"
    transaction = conn.pipeline()
    for key, tier in zip(keys, tiers, strict=True):
        transaction.zremrangebyscore(key, 0, now - tier.window)
        transaction.zadd(key, {member: now})
        transaction.expire(key, tier.window * 2)
        transaction.zcard(key)
        transaction.zrange(key, 0, 0, withscores=True)
    results = await transaction.execute()
    for index, tier in enumerate(tiers):
        count = int(results[index * _PIPELINE_COMMANDS_PER_TIER + 3])
        if count > tier.limit:
            oldest = results[index * _PIPELINE_COMMANDS_PER_TIER + 4]
            oldest_hit = float(oldest[0][1]) if oldest else None
            retry_after = _retry_after_seconds(oldest_hit, tier.window, now)
            withdraw = conn.pipeline()
            for key in keys:
                withdraw.zrem(key, member)
            await withdraw.execute()
            return index, count, retry_after
    return None
