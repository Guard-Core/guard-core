"""Perf gate: head tree against the v4.4.0 tree, per-request cost (D-162).

usage: python -m perf_gate.gate --head <tree> --base <v4.4.0 tree>
    --redis-url <url> [--summary <markdown file>]
Parts: calls (A/A first, exact), instructions (valgrind callgrind Ir, one
process per arm, collected only inside the measured loop), cpu (report only).
Exit 0 pass, 1 a row is above v4.4.0, 3 the gate is broken (the A/A of v4.4.0
against itself differs).

Calls count the measuring thread only (sys.setprofile is per thread), with the
event-loop iteration and done-callback frames skipped. cProfile counts every
thread from 3.12 on, so the ledger tools (perf/block_bench.py and friends) match
this counter on 3.10 only; a 3.14 ledger matrix is all-threads. Worker-thread
regex work is gated by Ir, which sees every thread.
"""

import argparse
import subprocess
import sys
import sysconfig

from perf_gate import compare
from perf_gate.run import ALL_ROWS

KEYS = {
    "calls": "calls_per_request",
    "instructions": "ir_per_request",
    "cpu": "cpu_us_per_request",
}


def measure(
    engine: str, mode: str, url: str, rows: list[str], jobs: int = 1
) -> dict[str, float]:
    cmd = [
        sys.executable,
        "-m",
        "perf_gate.run",
        "--engine",
        engine,
        "--mode",
        mode,
        "--redis-url",
        url,
        "--rows",
        ",".join(rows),
        "--jobs",
        str(jobs),
    ]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    return compare.parse_rows(out, KEYS[mode])


def collect(
    engine: str, mode: str, url: str, rows: list[str], runs: int, jobs: int
) -> dict[str, list[float]]:
    series: dict[str, list[float]] = {r: [] for r in rows}
    for _ in range(runs):
        for row, value in measure(engine, mode, url, rows, jobs).items():
            series[row].append(value)
    return series


def md_row(*cells: object) -> str:
    return "| " + " | ".join(str(c) for c in cells) + " |"


def calls_part(a: argparse.Namespace, rows: list[str], lines: list[str]) -> int:
    base = measure(a.base, "calls", a.redis_url, rows)
    base_again = measure(a.base, "calls", a.redis_url, rows)
    broken = compare.aa_differences(base, base_again)
    lines += [
        "",
        "### Calls per request: A/A (v4.4.0 against v4.4.0)",
        "",
        f"rows differing: {broken or 'none'}",
    ]
    for r in broken:
        lines.append(f"- {r}: {base.get(r)} then {base_again.get(r)}")
    if broken:
        lines.append("GATE BROKEN: the call-count A/A must show 0 difference")
        return 3
    head = measure(a.head, "calls", a.redis_url, rows)
    failed = compare.calls_failures(head, base)
    lines += [
        "",
        "### Calls per request, head against v4.4.0",
        "",
        "| row | v4.4.0 | head | % | verdict |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        pct = f"{compare.percent(head[r], base[r]):+.2f}"
        verdict = "FAIL" if r in failed else "ok"
        lines.append(md_row(r, base[r], head[r], pct, verdict))
    return 1 if failed else 0


def compile_bytecode_once(a: argparse.Namespace) -> None:
    """Byte-compile both trees and the venv so no counted run compiles source.

    A run that finds no .pyc compiles every module, hundreds of millions of
    instructions that the next run does not pay; this was the start-up spread.
    """
    targets = [f"{a.head}/guard_core", f"{a.base}/guard_core"]
    targets.append(sysconfig.get_paths()["purelib"])
    subprocess.run([sys.executable, "-m", "compileall", "-q", *targets], check=True)


def instructions_part(a: argparse.Namespace, rows: list[str], lines: list[str]) -> int:
    compile_bytecode_once(a)
    base = collect(a.base, "instructions", a.redis_url, rows, a.k0, a.jobs)
    head = collect(a.head, "instructions", a.redis_url, rows, a.k0, a.jobs)
    spread_rows = [r for r in rows if max(base[r]) != min(base[r])]
    if spread_rows:
        more = compare.MIN_RUNS_WITH_SPREAD - a.k0
        extra_base = collect(
            a.base, "instructions", a.redis_url, spread_rows, more, a.jobs
        )
        extra_head = collect(
            a.head, "instructions", a.redis_url, spread_rows, more, a.jobs
        )
        for r in spread_rows:
            base[r] += extra_base[r]
            head[r] += extra_head[r]
    lines += [
        "",
        "### Simulated instructions per request, head against v4.4.0",
        "",
        md_row(
            "row",
            "v4.4.0 min",
            "head max",
            "%",
            "rule",
            "spread",
            "K",
            "alarm",
            "verdict",
        ),
        "|---|---|---|---|---|---|---|---|---|",
    ]
    rc = 0
    for r in rows:
        v = compare.instruction_verdict(base[r], head[r])
        alarm = "" if v.false_alarm is None else f"{v.false_alarm:.1e}"
        lines.append(
            md_row(
                r,
                f"{min(base[r]):.0f}",
                f"{max(head[r]):.0f}",
                f"{v.percent_vs_base:+.3f}",
                v.rule,
                f"{v.base_spread:.0f}",
                v.runs_per_arm,
                alarm,
                v.status,
            )
        )
        rc = 1 if v.status != "pass" else rc
    return rc


def cpu_part(a: argparse.Namespace, rows: list[str], lines: list[str]) -> None:
    lines += [
        "",
        "### CPU per request (report only, interleaved rounds, with its own A/A)",
        "",
        "| row | v4.4.0 us | v4.4.0 again us | A/A % | head us | head % |",
        "|---|---|---|---|---|---|",
    ]
    runs: dict[str, dict[str, list[float]]] = {
        k: {r: [] for r in rows} for k in ("base", "again", "head")
    }
    for _ in range(a.cpu_rounds):
        for arm, tree in (("base", a.base), ("head", a.head), ("again", a.base)):
            for r, value in measure(tree, "cpu", a.redis_url, rows).items():
                runs[arm][r].append(value)
    for r in rows:
        b, g, h = (
            sorted(runs[k][r])[len(runs[k][r]) // 2] for k in ("base", "again", "head")
        )
        aa, hd = f"{compare.percent(g, b):+.1f}", f"{compare.percent(h, b):+.1f}"
        lines.append(md_row(r, b, g, aa, h, hd))


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--head", required=True)
    p.add_argument("--base", required=True)
    p.add_argument("--redis-url", required=True)
    p.add_argument("--rows", default=",".join(ALL_ROWS))
    p.add_argument("--instruction-rows", default="")
    p.add_argument("--cpu-rows", default="")
    p.add_argument("--parts", default="calls,instructions,cpu")
    p.add_argument("--k0", type=int, default=2)
    p.add_argument("--jobs", type=int, default=1)
    p.add_argument("--cpu-rounds", type=int, default=3)
    p.add_argument("--summary", default="")
    a = p.parse_args()
    rows, parts = a.rows.split(","), a.parts.split(",")
    lines = ["## Perf gate: per-request cost, head against v4.4.0"]
    codes = []
    if "calls" in parts:
        codes.append(calls_part(a, rows, lines))
    if "instructions" in parts and 3 not in codes:
        codes.append(
            instructions_part(a, (a.instruction_rows or a.rows).split(","), lines)
        )
    if "cpu" in parts:
        cpu_part(a, (a.cpu_rows or a.rows).split(","), lines)
    verdict = 3 if 3 in codes else int(any(codes))
    lines += ["", f"GATE {'BROKEN' if verdict == 3 else 'FAIL' if verdict else 'PASS'}"]
    print("\n".join(lines))
    if a.summary:
        with open(a.summary, "a") as f:
            f.write("\n".join(lines) + "\n")
    return verdict


if __name__ == "__main__":
    sys.exit(main())
