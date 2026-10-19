from dataclasses import dataclass, field

BODY_READ_STALLED = "stalled"
BODY_READ_FAILED = "failed"


@dataclass
class DetectionResult:
    is_threat: bool
    trigger_info: str
    threat_categories: list[str] = field(default_factory=list)
    threat_scores: dict[str, float] = field(default_factory=dict)
    body_read_error: str | None = None
    body_read_detail: str = ""
