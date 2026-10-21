from dataclasses import dataclass

from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

USAGE_MARKS_ATTR = "_guard_usage_marks"


@dataclass(frozen=True)
class UsageMarks:
    result: GuardResponse | None
    global_usage_rule_ids: frozenset[str]


def usage_marks_of(request: SyncGuardRequest) -> UsageMarks | None:
    marks = getattr(request.state, USAGE_MARKS_ATTR, None)
    return marks if isinstance(marks, UsageMarks) else None


def mark_usage_rules_evaluated(
    request: SyncGuardRequest,
    result: GuardResponse | None,
    global_usage_rule_ids: frozenset[str],
) -> None:
    setattr(request.state, USAGE_MARKS_ATTR, UsageMarks(result, global_usage_rule_ids))
