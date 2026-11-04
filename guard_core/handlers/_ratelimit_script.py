"""The rate limiter's Lua script call, reloaded once when Redis lost it."""

import logging
from collections.abc import Awaitable, Callable, Sequence
from typing import TYPE_CHECKING

from guard_core._redis_exceptions import NoScriptError
from guard_core.handlers._ratelimit_pipeline_fallback import _Tier
from guard_core.scripts.rate_lua import RATE_LIMIT_SCRIPT

if TYPE_CHECKING:
    from redis.asyncio import Redis

_Reply = Sequence[str | bytes | int | float]


def _script_arguments(tiers: Sequence[_Tier]) -> list[int]:
    return [value for tier in tiers for value in (tier.limit, tier.window)]


async def _evalsha_tiers(
    conn: "Redis",
    logger: logging.Logger,
    script_sha: str,
    keys: list[str],
    tiers: Sequence[_Tier],
    on_script_reloaded: Callable[[], Awaitable[None]] | None,
) -> tuple[_Reply, str]:
    arguments = _script_arguments(tiers)
    try:
        return await conn.evalsha(script_sha, len(keys), *keys, *arguments), script_sha
    except NoScriptError:
        script_sha = await conn.script_load(RATE_LIMIT_SCRIPT)
        logger.info("Rate limit Lua script reloaded after NOSCRIPT")
        if on_script_reloaded is not None:
            await on_script_reloaded()
        return await conn.evalsha(script_sha, len(keys), *keys, *arguments), script_sha
