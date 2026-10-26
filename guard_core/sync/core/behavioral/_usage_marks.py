from typing import NamedTuple

from guard_core.protocols.response_protocol import GuardResponse

USAGE_MARKS_ATTR = "_guard_usage_marks"


class UsageMarks(NamedTuple):
    result: GuardResponse | None
    global_usage_rule_ids: frozenset[str]


def usage_marks_of(state: object) -> UsageMarks | None:
    marks = getattr(state, USAGE_MARKS_ATTR, None)
    return marks if isinstance(marks, UsageMarks) else None


def mark_usage_rules_evaluated(
    state: object,
    result: GuardResponse | None,
    global_usage_rule_ids: frozenset[str],
) -> None:
    setattr(state, USAGE_MARKS_ATTR, UsageMarks(result, global_usage_rule_ids))
