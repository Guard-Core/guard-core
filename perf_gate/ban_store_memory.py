"""Python heap held by the in-memory ban store when it is full.

usage: PYTHONPATH=<tree with guard_core/> python -m perf_gate.ban_store_memory
    [--family 4|6] [--entries N]
Bans N distinct addresses (default `banned_ips_max_entries`, 100,000) through
`IPBanManager.ban_ip` and prints one JSON line: the entries held, the bytes
tracemalloc holds for them, and the bytes per entry.
"""

import argparse
import asyncio
import gc
import json
import logging
import sys
import tracemalloc


def address(index: int, family: str) -> str:
    if family == "4":
        return f"{20 + index // 65536}.{(index // 256) % 256}.{index % 256}.7"
    return f"2a00:{(index >> 16) & 0xFFFF:x}:{index & 0xFFFF:x}::1"


def held_bytes(entries: int, family: str) -> tuple[int, int]:
    from guard_core.handlers.ipban_handler import IPBanManager
    from guard_core.models import SecurityConfig

    manager = IPBanManager._fresh()
    manager.config = SecurityConfig()
    manager.set_capacity(max(entries, 1))

    async def fill() -> None:
        for index in range(entries):
            await manager.ban_ip(address(index, family), 3600)

    gc.collect()
    before = tracemalloc.get_traced_memory()[0]
    asyncio.run(fill())
    gc.collect()
    return len(manager.banned_ips), tracemalloc.get_traced_memory()[0] - before


def main(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--family", choices=["4", "6"], default="4")
    parser.add_argument("--entries", type=int, default=100_000)
    args = parser.parse_args(argv)
    logging.disable(logging.CRITICAL)
    tracemalloc.start()
    held, size = held_bytes(args.entries, args.family)
    print(
        json.dumps(
            {
                "family": args.family,
                "entries": held,
                "mib": round(size / 1048576, 2),
                "bytes_per_entry": round(size / held),
            }
        )
    )


if __name__ == "__main__":
    main(sys.argv[1:])
