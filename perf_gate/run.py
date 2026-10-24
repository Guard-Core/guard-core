"""Entry point of the perf gate: one machine-readable line per row for one engine tree.

usage: python -m perf_gate.run --engine <tree with guard_core/>
    --mode <calls|instructions|cpu> --redis-url <url>
Each line is `ROW <json>` with keys mode, row and the mode's value:
calls -> calls_per_request, instructions -> ir_per_request (Ir at 2N minus Ir
at N, over N), cpu -> cpu_us_per_request.
Rows run in a child process with PYTHONPATH=<engine> and PYTHONHASHSEED=0.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

ROWS_SCRIPT = Path(__file__).with_name("rows.py")
ALL_ROWS = (
    ["ban_check"]
    + [f"allowed-{k}-redis-{m}" for k in ("get", "post") for m in ("off", "on")]
    + [
        f"blocked-{s}-pen{p}-redis{m}"
        for s in ("blacklist", "banned")
        for p in (1, 0)
        for m in ("off", "on")
    ]
    + [f"blocked-pattern-redis{m}" for m in ("off", "on")]
)
IR_LINE = re.compile(r"I\s+refs:\s+([\d,]+)")
COLLECTED = re.compile(r"Collected\s*:\s*(\d+)")


def child_env(engine: str) -> dict[str, str]:
    return {
        **os.environ,
        "PYTHONPATH": engine,
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def uses_redis(row: str) -> bool:
    return row == "ban_check" or row.endswith("redis-on") or row.endswith("redison")


def row_command(row: str, mode: str, n: int, url: str, rounds: int) -> list[str]:
    redis_url = url if uses_redis(row) else ""
    return [sys.executable, str(ROWS_SCRIPT), row, mode, str(n), redis_url, str(rounds)]


def run_row(
    engine: str, row: str, mode: str, n: int, url: str, rounds: int
) -> dict[str, Any]:
    proc = subprocess.run(
        row_command(row, mode, n, url, rounds),
        env=child_env(engine),
        capture_output=True,
        text=True,
        check=True,
    )
    result: dict[str, Any] = json.loads(proc.stdout.strip().splitlines()[-1])
    return result


def valgrind_instructions(engine: str, row: str, n: int, url: str) -> int:
    with tempfile.TemporaryDirectory() as tmp:
        cmd = [
            "valgrind",
            "--tool=cachegrind",
            "--cache-sim=no",
            f"--cachegrind-out-file={tmp}/cg.out",
            *row_command(row, "run", n, url, 1),
        ]
        proc = subprocess.run(
            cmd, env=child_env(engine), capture_output=True, text=True, check=True
        )
    match = IR_LINE.search(proc.stderr)
    if match is None:
        raise RuntimeError(f"no Ir line for {row}: {proc.stderr[-400:]}")
    return int(match.group(1).replace(",", ""))


def valgrind_window_instructions(engine: str, row: str, n: int, url: str) -> int:
    """Ir of the n measured requests only: callgrind collects inside one C call."""
    with tempfile.TemporaryDirectory() as tmp:
        cmd = [
            "valgrind",
            "--tool=callgrind",
            "--collect-atstart=no",
            "--toggle-collect=PyRun_SimpleString*",
            f"--callgrind-out-file={tmp}/cg.out",
            *row_command(row, "window", n, url, 1),
        ]
        proc = subprocess.run(
            cmd, env=child_env(engine), capture_output=True, text=True, check=True
        )
    match = COLLECTED.search(proc.stderr)
    if match is None:
        raise RuntimeError(f"no Collected line for {row}: {proc.stderr[-400:]}")
    return int(match.group(1))


def measure(
    engine: str, row: str, mode: str, n: int, url: str, rounds: int
) -> dict[str, Any]:
    if mode == "instructions" and os.environ.get("PERF_GATE_IR") != "difference":
        ir = valgrind_window_instructions(engine, row, n, url)
        return {"ir_per_request": ir / n, "ir_window": ir}
    if mode == "instructions":
        ir_n = valgrind_instructions(engine, row, n, url)
        ir_2n = valgrind_instructions(engine, row, 2 * n, url)
        return {"ir_per_request": (ir_2n - ir_n) / n, "ir_n": ir_n, "ir_2n": ir_2n}
    return run_row(engine, row, mode, n, url, rounds)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", required=True)
    parser.add_argument(
        "--mode", choices=("calls", "instructions", "cpu", "workers"), required=True
    )
    parser.add_argument("--redis-url", required=True)
    parser.add_argument("--rows", default=",".join(ALL_ROWS))
    parser.add_argument("--n", type=int, default=0)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--jobs", type=int, default=1)
    args = parser.parse_args()
    n = (
        args.n
        or {"calls": 200, "instructions": 25, "cpu": 300, "workers": 200}[args.mode]
    )
    rows = args.rows.split(",")
    jobs = args.jobs if args.mode == "instructions" else 1
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = [
            pool.submit(
                measure, args.engine, r, args.mode, n, args.redis_url, args.rounds
            )
            for r in rows
        ]
        for row, future in zip(rows, futures, strict=True):
            result = future.result()
            print("ROW " + json.dumps({"mode": args.mode, "row": row, **result}))
            sys.stdout.flush()


if __name__ == "__main__":
    main()
