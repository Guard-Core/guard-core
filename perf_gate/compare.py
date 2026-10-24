"""Pure comparison rules of the perf gate (D-162).

Parsing of row lines, the call-count rule and the instruction rule.
"""

import json
from dataclasses import dataclass
from math import comb
from typing import Any

MIN_RUNS_WITH_SPREAD = 8


def parse_rows(text: str, value_key: str) -> dict[str, float]:
    """`ROW <json>` lines to {row: value}; a repeated row is an error."""
    values: dict[str, float] = {}
    for line in text.splitlines():
        if not line.startswith("ROW "):
            continue
        record: dict[str, Any] = json.loads(line[4:])
        row = record["row"]
        if row in values:
            raise ValueError(f"row {row} printed twice")
        values[row] = float(record[value_key])
    return values


def aa_differences(first: dict[str, float], second: dict[str, float]) -> list[str]:
    """Rows whose A/A values differ; an empty list is a working gate."""
    return sorted(
        r for r in first.keys() | second.keys() if first.get(r) != second.get(r)
    )


def percent(head: float, base: float) -> float:
    return 100.0 * (head - base) / base


def calls_failures(head: dict[str, float], base: dict[str, float]) -> list[str]:
    return sorted(r for r in base if head[r] > base[r])


def false_alarm_rate(runs_per_arm: int) -> float:
    """Chance that disjoint arms order head above base by luck: 1 / C(2K, K)."""
    return 1 / comb(2 * runs_per_arm, runs_per_arm)


@dataclass(frozen=True)
class InstructionVerdict:
    status: str  # "pass", "fail" or "needs_more_runs"
    rule: str  # "exact" or "disjoint"
    base_spread: float
    runs_per_arm: int
    percent_vs_base: float
    false_alarm: float | None


def instruction_verdict(base: list[float], head: list[float]) -> InstructionVerdict:
    """Spread 0: head <= base exactly. Spread above 0: K >= 8 per arm.

    With spread the row fails only when head min > base max.
    """
    spread = max(base) - min(base)
    runs = min(len(base), len(head))
    if spread == 0:
        pct = percent(max(head), base[0])
        return InstructionVerdict(
            "fail" if max(head) > base[0] else "pass", "exact", 0.0, runs, pct, None
        )
    pct = percent(sorted(head)[len(head) // 2], sorted(base)[len(base) // 2])
    alarm = false_alarm_rate(runs)
    if runs < MIN_RUNS_WITH_SPREAD:
        return InstructionVerdict(
            "needs_more_runs", "disjoint", spread, runs, pct, alarm
        )
    status = "fail" if min(head) > max(base) else "pass"
    return InstructionVerdict(status, "disjoint", spread, runs, pct, alarm)
