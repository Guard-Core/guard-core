import os
import subprocess
import sys

import redis

from tests.conftest import suite_redis_prefix

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
SCRIPT = """
import asyncio, sys
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig

async def main(url, prefix, duration, ips):
    config = SecurityConfig(redis_url=url, redis_prefix=prefix, enable_redis=True)
    redis_handler = RedisManager(config)
    await redis_handler.initialize()
    ip_ban_manager.config = config
    ip_ban_manager.redis_handler = redis_handler
    worker = DynamicRuleManager(config)
    worker.redis_handler = redis_handler
    created, skipped = [], []
    await worker._apply_ip_bans(ips, int(duration), created, skipped)
    await redis_handler.close()

asyncio.run(main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]))
"""


def _apply_in_a_new_process(prefix: str, duration: int, ips: list[str]) -> None:
    subprocess.run(
        [sys.executable, "-c", SCRIPT, REDIS_URL, prefix, str(duration), *ips],
        check=True,
        capture_output=True,
        timeout=60,
    )


def test_two_processes_applying_overlapping_sets_both_record_their_bans() -> None:
    prefix = suite_redis_prefix("wp17-two-proc")
    shared, first_only, second_only = "198.51.100.70", "198.51.100.71", "198.51.100.72"

    _apply_in_a_new_process(prefix, 3600, [shared, first_only])
    _apply_in_a_new_process(prefix, 7200, [shared, second_only])

    client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    try:
        owned = dict(
            client.zrange(f"{prefix}dynamic_rules:owned_bans", 0, -1, withscores=True)
        )
        assert set(owned) == {
            f"{prefix}banned_ips:{ip}" for ip in (shared, first_only, second_only)
        }
        for ip in (shared, first_only, second_only):
            value = client.get(f"{prefix}banned_ips:{ip}")
            assert owned[f"{prefix}banned_ips:{ip}"] == float(value)
        assert client.ttl(f"{prefix}banned_ips:{shared}") > 7190
        assert client.ttl(f"{prefix}banned_ips:{first_only}") <= 3600
    finally:
        for key in client.scan_iter(match=f"{prefix}*"):
            client.delete(key)
        client.close()
