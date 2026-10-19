from guard_core._utils.logging_utils import _sanitize_for_reporting
from guard_core.detection_result import (
    BODY_READ_FAILED,
    BODY_READ_STALLED,
    DetectionResult,
)


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
    for threat in threats:
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
