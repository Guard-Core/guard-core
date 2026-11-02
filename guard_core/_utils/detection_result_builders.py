from guard_core._utils.logging_utils import _sanitize_for_reporting
from guard_core.detection_result import (
    BODY_READ_FAILED,
    BODY_READ_QUEUE_WAIT,
    BODY_READ_STALLED,
    DetectionResult,
)
from guard_core.exceptions import BodyReadFailedError, RegexQueueWaitError


def _threat_category(threat: dict) -> str | None:
    if threat.get("type") == "regex":
        category = threat.get("category")
        return category if isinstance(category, str) else None
    if threat.get("type") == "semantic":
        attack_type = threat.get("attack_type")
        return attack_type if isinstance(attack_type, str) else None
    return None


def _threat_score(threat: dict) -> float:
    if "probability" in threat:
        return float(threat["probability"])
    if "threat_score" in threat:
        return float(threat["threat_score"])
    return 1.0


def _build_detection_hit(trigger: str, threats: list[dict]) -> DetectionResult:
    categories: list[str] = []
    scores: dict[str, float] = {}
    first_regex_source: str | None = None
    for threat in threats:
        if first_regex_source is None and threat.get("type") == "regex":
            candidate = threat.get("pattern")
            first_regex_source = candidate if isinstance(candidate, str) else None
        category = _threat_category(threat)
        if category is None:
            continue
        if category not in categories:
            categories.append(category)
        score = _threat_score(threat)
        scores[category] = max(scores.get(category, 0.0), score)
    return DetectionResult(
        is_threat=True,
        trigger_info=_sanitize_for_reporting(trigger),
        threat_categories=categories,
        threat_scores=scores,
        matched_pattern_source=first_regex_source,
    )


def _build_detection_miss() -> DetectionResult:
    return DetectionResult(is_threat=False, trigger_info="")


def _build_body_read_error(stalled: bool, detail: str) -> DetectionResult:
    return DetectionResult(
        is_threat=False,
        trigger_info="",
        body_read_error=BODY_READ_STALLED if stalled else BODY_READ_FAILED,
        body_read_detail=_sanitize_for_reporting(detail),
    )


def _build_queue_wait_error(error: RegexQueueWaitError) -> DetectionResult:
    return DetectionResult(
        is_threat=False,
        trigger_info="",
        body_read_error=BODY_READ_QUEUE_WAIT,
        body_read_detail=_sanitize_for_reporting(error.detail),
        queue_wait_seconds=error.waited,
        queue_wait_surface=error.surface,
    )


def _build_read_error_of(error: BodyReadFailedError) -> DetectionResult:
    if isinstance(error, RegexQueueWaitError):
        return _build_queue_wait_error(error)
    return _build_body_read_error(False, error.detail)
