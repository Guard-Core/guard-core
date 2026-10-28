from typing import TYPE_CHECKING

from guard_core.sync.handlers._suspatterns_sources import (
    _SELECT_FROM_RE,
    _SELECT_STAR_RE,
    _WHERE_CLAUSE_RE,
    ALL_DETECTION_CATEGORIES,
)

if TYPE_CHECKING:
    from guard_core.protocols.agent_protocol import JsonValue


DETECTION_CATEGORY_WEIGHTS: dict[str, float] = {
    category: 1.0 for category in ALL_DETECTION_CATEGORIES
}

DETECTION_PATTERN_WEIGHT_OVERRIDES: dict[str, float] = {
    _SELECT_FROM_RE: 0.5,
    _SELECT_STAR_RE: 0.5,
    _WHERE_CLAUSE_RE: 0.5,
}


def _resolve_pattern_weight(pattern: str, category: str) -> float:
    if pattern in DETECTION_PATTERN_WEIGHT_OVERRIDES:
        return DETECTION_PATTERN_WEIGHT_OVERRIDES[pattern]
    return DETECTION_CATEGORY_WEIGHTS.get(category, 1.0)


_DECODE_BUDGET_EXHAUSTED_PATTERN = "decode_budget_exhausted"


def _decode_budget_exhausted_threat() -> dict[str, "JsonValue"]:
    return {
        "type": "regex",
        "pattern": _DECODE_BUDGET_EXHAUSTED_PATTERN,
        "match": _DECODE_BUDGET_EXHAUSTED_PATTERN,
        "position": 0,
        "execution_time": 0.0,
        "category": "custom",
        "weight": _resolve_pattern_weight(_DECODE_BUDGET_EXHAUSTED_PATTERN, "custom"),
    }
