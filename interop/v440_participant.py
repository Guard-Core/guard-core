"""Reader of the mixed-fleet custom-pattern case: a real guard-core v4.4.0 engine.

run.py starts this file with the v4.4.0 checkout's own interpreter and that
checkout on PYTHONPATH, so every import below is v4.4.0's code. It restores the
custom patterns from the Redis prefix it is given exactly as v4.4.0 does at
startup and reports what it restored and what its detector flags. The Go and PHP
phases are then held to this report, never to a hard-coded list.
"""

import asyncio
import json
import logging
import os
from pathlib import Path

from guard_core.handlers.redis_handler import RedisManager
from guard_core.handlers.suspatterns_handler import (
    SusPatternsManager,
    sus_patterns_handler,
)
from guard_core.models import SecurityConfig

PROBE_PATHS = ("/api/users", "/health", "/zq_marker_hit", "/alpha_pattern")


async def main() -> int:
    logging.disable(logging.CRITICAL)
    incoming = json.loads(os.environ.get("INTEROP_INPUT", "{}"))
    port = os.environ.get("REDIS_PORT", "6379")
    config = SecurityConfig(
        redis_url=f"redis://127.0.0.1:{port}",
        redis_prefix=f"{incoming['prefix_root']}mf_v440:",
        enable_redis=True,
        rate_limit=10000,
    )
    redis = RedisManager(config)
    await redis.initialize()
    await SusPatternsManager.reset()
    sus_patterns_handler.configure(config)
    await sus_patterns_handler.initialize_redis(redis)
    patterns = sorted(sus_patterns_handler.custom_patterns)
    flagged = {}
    for path in PROBE_PATHS:
        verdict = await sus_patterns_handler.detect(path, "127.0.0.1", "request_path")
        flagged[path] = bool(verdict["is_threat"])
    await redis.close()
    checks: list[dict[str, object]] = [
        {
            "scenario": "custom_patterns_v440_read",
            "direction": "py_v440:py_v440",
            "name": "v4.4.0 restores the patterns the head wrote",
            "passed": bool(patterns),
            "detail": json.dumps(patterns),
        }
    ]
    failed = sum(1 for c in checks if not c["passed"])
    report = {
        "participant": "python_v440",
        "phase": "v440_custom_patterns_read",
        "passed": len(checks) - failed,
        "failed": failed,
        "checks": checks,
        "artifacts": {
            "v440_patterns": json.dumps(patterns),
            "v440_flagged": json.dumps(flagged),
        },
    }
    Path(os.environ["INTEROP_REPORT_FILE"]).write_text(json.dumps(report, indent=2))
    print(f"v4.4.0 restored {patterns}, flagged {flagged}")
    return int(failed)


raise SystemExit(asyncio.run(main()))
