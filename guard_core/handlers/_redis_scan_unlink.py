from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redis.asyncio import Redis

SCAN_BATCH = 500


async def scan_unlink(
    conn: Redis, full_pattern: str, select: Callable[[str], bool] | None = None
) -> int:
    """Delete every key matching full_pattern (and select, when given): one SCAN
    cursor walk, UNLINK in batches. Never KEYS, which walks the whole keyspace in
    one blocking command."""
    removed = 0
    batch: list[str] = []
    async for key in conn.scan_iter(match=full_pattern, count=SCAN_BATCH):
        if select is not None and not select(key):
            continue
        batch.append(key)
        if len(batch) >= SCAN_BATCH:
            removed += int(await conn.unlink(*batch))
            batch.clear()
    return removed + await _unlink_remaining(conn, batch)


async def _unlink_remaining(conn: Redis, batch: list[str]) -> int:
    return int(await conn.unlink(*batch)) if batch else 0
