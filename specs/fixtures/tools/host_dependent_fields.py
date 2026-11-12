"""The fields of the committed corpus that a regeneration measures on the host.

Two readers compare a fresh run with a committed corpus: the determinism proof in
generate_fixtures.py and tests/test_fixture_generator_determinism.py. Both mask
exactly the paths listed here and nothing else, so a verdict, an expected event, a
key or a pinned byte that changes is always a real corpus change.

Every entry names the file, the JSON path (``*`` is every list element or dict
value) and the line that writes it.
"""

from __future__ import annotations

import copy
from typing import TypeVar

Payload = TypeVar("Payload")

HOST_DEPENDENT_FIELDS: dict[str, dict[tuple[str, ...], str]] = {
    "index.json": {
        ("engine_commit",): "generate_fixtures.py engine_commit(): git rev-parse HEAD",
        ("generated_at",): "generate_fixtures.py build_index: the wall clock",
        (
            "cost_budgets",
            "generated_at",
        ): "generate_cost_cases.py: the wall clock of the cost run",
        (
            "cost_budgets",
            "budgets",
            "*",
            "reference_ms",
        ): "generate_cost_cases.py: best of 5 timings of the engine on the host",
    },
    "safety_gates.json": {
        (
            "cases",
            "*",
            "reference",
            "extrapolated_seconds",
        ): "generate_safety_gates.py _fixed_reference: the extrapolated cost the "
        "timed probe measured (over_budget)",
        (
            "cases",
            "*",
            "reference",
            "margin",
        ): "generate_safety_gates.py _fixed_reference: extrapolated_seconds over "
        "the budget (over_budget)",
        (
            "cases",
            "*",
            "reference",
            "observed_cpu_seconds",
        ): "generate_safety_gates.py _fixed_reference: CPU seconds of the string "
        "probe (probe_string_timeout)",
        (
            "cases",
            "*",
            "reference",
            "margin_over_threshold",
        ): "generate_safety_gates.py _fixed_reference: observed_cpu_seconds over "
        "the threshold (probe_string_timeout)",
        (
            "cases",
            "*",
            "reference",
            "margin_under_kill",
        ): "generate_safety_gates.py _fixed_reference: the kill limit over "
        "observed_cpu_seconds (probe_string_timeout)",
        (
            "cases",
            "*",
            "reference",
            "load_average_at_generation",
        ): "generate_safety_gates.py _fixed_reference: os.getloadavg() of the host",
    },
}


def _drop(node: object, path: tuple[str, ...]) -> None:
    head, rest = path[0], path[1:]
    if head == "*":
        if isinstance(node, dict):
            node = list(node.values())
        if isinstance(node, list):
            for child in node:
                _drop(child, rest)
        return
    if not isinstance(node, dict) or head not in node:
        return
    if rest:
        _drop(node[head], rest)
    else:
        del node[head]


def without_host_fields(file_name: str, payload: Payload) -> Payload:
    """A copy of the parsed corpus file with its host-dependent fields removed."""
    masked = copy.deepcopy(payload)
    for path in HOST_DEPENDENT_FIELDS.get(file_name, {}):
        _drop(masked, path)
    return masked
