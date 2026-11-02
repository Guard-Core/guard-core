"""The hit rate of the detection caches over two boots on one validation cache file.

usage: python -m perf_gate.cache_hit_rate [patterns]

Adds `patterns` custom patterns (default 20) to a fresh pattern manager that has
`detection_pattern_validation_cache_path` set, twice, as two process boots would,
and prints one JSON line per boot with `SusPatternsManager.get_cache_stats()`.
"""

import asyncio
import json
import sys
import tempfile
from pathlib import Path

from guard_core.handlers.suspatterns_handler import SusPatternsManager
from guard_core.models import SecurityConfig


async def boot_cache_stats(cache_file: Path, patterns: int) -> dict[str, object]:
    SusPatternsManager._instance = None
    manager = SusPatternsManager()
    manager.configure(
        SecurityConfig(detection_pattern_validation_cache_path=str(cache_file))
    )
    for index in range(patterns):
        await manager.add_pattern(rf"customrule{index}[a-z]{{2,8}}\d", custom=True)
    return dict(await manager.get_cache_stats())


async def two_boots(patterns: int) -> list[dict[str, object]]:
    with tempfile.TemporaryDirectory() as directory:
        cache_file = Path(directory) / "validation.json"
        first = await boot_cache_stats(cache_file, patterns)
        second = await boot_cache_stats(cache_file, patterns)
    SusPatternsManager._instance = None
    return [first, second]


def main() -> None:
    patterns = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    boots = asyncio.run(two_boots(patterns))
    for boot, stats in zip(("first", "second"), boots, strict=True):
        print(json.dumps({"boot": boot, **stats}))


if __name__ == "__main__":
    main()
