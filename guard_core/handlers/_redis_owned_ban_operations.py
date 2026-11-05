from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from guard_core._redis_enablement import redis_is_configured
from guard_core._redis_exceptions import NoScriptError
from guard_core.handlers import _redis_handler_support as redis_types
from guard_core.handlers._dynamic_rule_persistence import BAN_FLOORS_NAMESPACE
from guard_core.scripts.ban_write_lua import (
    EXTEND_ONLY_BAN_WRITE_SCRIPT,
    PURGE_OWNED_BAN_SCRIPT,
)

if TYPE_CHECKING:
    from redis.asyncio import Redis

    from guard_core.handlers.redis_handler import RedisManager

_EXTEND_ONLY_BAN_WRITE_SHA = hashlib.sha1(
    EXTEND_ONLY_BAN_WRITE_SCRIPT.encode(), usedforsecurity=False
).hexdigest()
_PURGE_OWNED_BAN_SHA = hashlib.sha1(
    PURGE_OWNED_BAN_SCRIPT.encode(), usedforsecurity=False
).hexdigest()


async def write_ban_extending_only(
    manager: RedisManager,
    namespace: str,
    key: str,
    expiry: str,
    duration: int,
    *,
    version: tuple[str, str],
    advance_version: bool = False,
    rule_owned: bool = False,
) -> float:
    if not redis_is_configured(manager.config):
        return float(expiry)

    prefix = manager.config.redis_prefix
    keys = [
        f"{prefix}{namespace}:{key}",
        f"{prefix}{version[0]}:{version[1]}",
        manager._owned_bans_key(),
        manager.ban_floor_key(namespace, key),
    ]
    args: list[str | int] = [
        expiry,
        duration,
        "1" if advance_version else "0",
        "1" if rule_owned else "0",
    ]

    async def _write(conn: Redis) -> float:
        try:
            answer = await conn.evalsha(
                _EXTEND_ONLY_BAN_WRITE_SHA, len(keys), *keys, *args
            )
        except NoScriptError:
            await conn.script_load(EXTEND_ONLY_BAN_WRITE_SCRIPT)
            answer = await conn.evalsha(
                _EXTEND_ONLY_BAN_WRITE_SHA, len(keys), *keys, *args
            )
        return float(answer[1])

    expiry_held = await manager.safe_operation(_write)
    if expiry_held is None:
        raise TypeError(redis_types.NO_OPERATION_RESULT)
    return expiry_held


async def owned_ban_members(manager: RedisManager) -> list[str]:
    if not redis_is_configured(manager.config):
        return []

    async def _members(conn: Redis) -> list[str]:
        return [str(m) for m in await conn.zrange(manager._owned_bans_key(), 0, -1)]

    return list(await manager.safe_operation(_members) or [])


async def owned_ban_state(
    manager: RedisManager, namespace: str, key: str
) -> tuple[float | None, float | None]:
    if not redis_is_configured(manager.config):
        return None, None
    prefix = manager.config.redis_prefix
    member = f"{prefix}{namespace}:{key}"

    async def _state(conn: Redis) -> tuple[float | None, float | None]:
        async with conn.pipeline(transaction=False) as pipe:
            await pipe.zscore(manager._owned_bans_key(), member)
            await pipe.get(member)
            score, stored = await pipe.execute()
        return (
            None if score is None else float(score),
            None if not stored else float(stored),
        )

    state: tuple[float | None, float | None] | None = await manager.safe_operation(
        _state
    )
    return state if state is not None else (None, None)


async def purge_owned_ban(manager: RedisManager, member: str) -> int:
    prefix = manager.config.redis_prefix
    floor = f"{prefix}{BAN_FLOORS_NAMESPACE}:{member[len(prefix) :]}"
    keys = [member, manager._owned_bans_key(), floor]

    async def _purge(conn: Redis) -> int:
        try:
            return int(await conn.evalsha(_PURGE_OWNED_BAN_SHA, len(keys), *keys))
        except NoScriptError:
            await conn.script_load(PURGE_OWNED_BAN_SCRIPT)
            return int(await conn.evalsha(_PURGE_OWNED_BAN_SHA, len(keys), *keys))

    return int(await manager.safe_operation(_purge) or 0)


async def disown_ban(manager: RedisManager, namespace: str, key: str) -> None:
    if not redis_is_configured(manager.config):
        return

    member = f"{manager.config.redis_prefix}{namespace}:{key}"

    async def _disown(conn: Redis) -> None:
        await conn.zrem(manager._owned_bans_key(), member)

    await manager.safe_operation(_disown)
