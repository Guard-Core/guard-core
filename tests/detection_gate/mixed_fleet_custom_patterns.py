"""Mixed fleet gate (D-80 item 1, LEDGER 4.12): next to a real v4.4.0 engine.

Both engines run their own restore, add and remove code on one Redis. Local only: it
needs a v4.4.0 checkout with its own interpreter and a Redis nobody else uses.

    python -m tests.detection_gate.mixed_fleet_custom_patterns \
        LEGACY_TREE LEGACY_PYTHON REDIS_URL

Exit code 0 when every scenario matches, 1 otherwise.
"""

import asyncio
import json
import logging
import subprocess
import sys
import uuid
from collections.abc import Awaitable, Callable

from guard_core.handlers.redis_handler import RedisManager
from guard_core.handlers.suspatterns_handler import (
    SusPatternsManager,
    sus_patterns_handler,
)
from guard_core.models import SecurityConfig

COMMA_PATTERN = r"\bacct\d{1,3}\b"
LEGACY_ENGINE = r"""
import asyncio, json, logging, sys
logging.disable(logging.CRITICAL)
from guard_core.handlers.redis_handler import RedisManager
from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

url, prefix, action, pattern = sys.argv[1:5]


async def main():
    config = SecurityConfig(
        enable_redis=True, redis_url=url, redis_prefix=prefix,
        enable_penetration_detection=True, enable_rate_limiting=False,
    )
    redis = RedisManager(config)
    await redis.initialize()
    sus_patterns_handler.configure(config)
    await sus_patterns_handler.initialize_redis(redis)
    if action == "add":
        await sus_patterns_handler.add_pattern(pattern, custom=True)
    elif action == "remove":
        await sus_patterns_handler.remove_pattern(pattern, custom=True)
    verdicts = {}
    for path in ("/api/users", "/health", "/zq_marker_hit"):
        result = await detect_penetration_attempt(MockGuardRequest(path=path), config)
        verdicts[path] = bool(result.is_threat)
    print(json.dumps({"patterns": sorted(sus_patterns_handler.custom_patterns),
                      "flagged": verdicts}))
    await redis.close()


asyncio.run(main())
"""


def _legacy(
    tree: str, python: str, url: str, prefix: str, action: str, pattern: str = ""
) -> dict[str, object]:
    done = subprocess.run(
        [python, "-c", LEGACY_ENGINE, url, prefix, action, pattern],
        cwd=tree,
        env={"PYTHONPATH": tree, "IPINFO_TOKEN": "x", "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=True,
    )
    parsed: dict[str, object] = json.loads(done.stdout.strip().splitlines()[-1])
    return parsed


async def _new_engine(
    url: str, prefix: str, act: Callable[[], Awaitable[None]] | None = None
) -> set[str]:
    config = SecurityConfig(enable_redis=True, redis_url=url, redis_prefix=prefix)
    redis = RedisManager(config)
    await redis.initialize()
    await SusPatternsManager.reset()
    sus_patterns_handler.configure(config)
    await sus_patterns_handler.initialize_redis(redis)
    if act is not None:
        await act()
    restored = set(sus_patterns_handler.custom_patterns)
    await SusPatternsManager.reset()
    await redis.close()
    return restored


async def _wipe(url: str, prefix: str) -> None:
    config = SecurityConfig(enable_redis=True, redis_url=url, redis_prefix=prefix)
    redis = RedisManager(config)
    await redis.initialize()
    await redis.delete_pattern(f"{prefix}patterns:*")
    await redis.close()


async def main(tree: str, python: str, url: str) -> int:
    logging.disable(logging.CRITICAL)
    run = uuid.uuid4().hex[:8]
    checks: list[tuple[str, bool, object]] = []

    def record(name: str, ok: bool, detail: object) -> None:
        checks.append((name, ok, detail))
        print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}")

    async def write(prefix: str, patterns: list[str]) -> None:
        async def act() -> None:
            for pattern in patterns:
                await sus_patterns_handler.add_pattern(pattern, custom=True)

        await _new_engine(url, prefix, act)

    plain = f"{run}a:"
    await _wipe(url, plain)
    await write(plain, ["zq_marker_hit", "alpha_pattern"])
    seen = _legacy(tree, python, url, plain, "read")
    record(
        "v4.4.0 reads what this engine wrote (no commas)",
        seen["patterns"] == ["alpha_pattern", "zq_marker_hit"]
        and seen["flagged"]
        == {"/api/users": False, "/health": False, "/zq_marker_hit": True},
        seen,
    )

    _legacy(tree, python, url, plain, "add", "gamma_pattern")
    after_add = await _new_engine(url, plain)
    record(
        "a v4.4.0 add after this engine's write is seen",
        after_add == {"zq_marker_hit", "alpha_pattern", "gamma_pattern"},
        sorted(after_add),
    )
    _legacy(tree, python, url, plain, "remove", "alpha_pattern")
    after_remove = await _new_engine(url, plain)
    record(
        "a v4.4.0 remove after this engine's write is seen",
        after_remove == {"zq_marker_hit", "gamma_pattern"},
        sorted(after_remove),
    )

    ours, theirs = f"{run}b:", f"{run}c:"
    for prefix in (ours, theirs):
        await _wipe(url, prefix)
    await write(ours, [COMMA_PATTERN, "zq_marker_hit"])
    _legacy(tree, python, url, theirs, "add", COMMA_PATTERN)
    _legacy(tree, python, url, theirs, "add", "zq_marker_hit")
    own = _legacy(tree, python, url, theirs, "read")
    wrote_by_new = _legacy(tree, python, url, ours, "read")
    record(
        "a comma pattern of this engine is split by v4.4.0 as it splits its own",
        wrote_by_new == own,
        {"new_wrote": wrote_by_new["patterns"], "v440_wrote": own["patterns"]},
    )
    for prefix in (plain, ours, theirs):
        await _wipe(url, prefix)
    failed = [name for name, ok, _ in checks if not ok]
    print(f"{len(checks) - len(failed)} of {len(checks)} scenarios match")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(*sys.argv[1:4])))
