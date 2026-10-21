"""One process on a shared data dir: waits for a start time, then adopts the GeoIP
copy from Redis or downloads it, and prints what happened as one JSON line."""

import asyncio
import json
import sys
import time
from pathlib import Path

from guard_core.handlers.ipinfo_handler import IPInfoManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig


async def main(mode: str, url: str, prefix: str, db: str, start: float) -> None:
    IPInfoManager._instance = None
    manager = IPInfoManager(token="tok", db_path=Path(db))
    manager._max_age = 3600
    handler = None
    if mode == "adopt":
        config = SecurityConfig(
            redis_url=url,
            redis_prefix=prefix,
            enable_redis=True,
            rate_limit=10,
            ban_on_hostile_signals=False,
        )
        handler = RedisManager(config)
        await handler.initialize()
        manager.redis_handler = handler
    else:
        manager._download_url = url
        manager._download_retries = 1
    while time.time() < start:
        time.sleep(0.001)
    if handler is None:
        await manager._fetch_and_store_database()
        manager._apply_opened_reader(manager._open_database_or_none())
        print(json.dumps({"done": True, "country": manager.get_country("203.0.113.5")}))
        return
    adopted = await manager._adopt_redis_copy()
    async with handler.get_connection() as conn:
        survived = bool(await conn.exists(f"{prefix}ipinfo:database"))
    print(json.dumps({"done": adopted, "key_survived": survived}))
    await handler.close()


if __name__ == "__main__":
    mode, url, prefix, db, start = sys.argv[1:6]
    asyncio.run(main(mode, url, prefix, db, float(start)))
