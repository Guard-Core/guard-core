from dataclasses import dataclass, field

BODY_READ_STALLED = "stalled"
BODY_READ_FAILED = "failed"
BODY_READ_QUEUE_WAIT = "queue_wait"


@dataclass
class DetectionResult:
    is_threat: bool
    trigger_info: str
    threat_categories: list[str] = field(default_factory=list)
    threat_scores: dict[str, float] = field(default_factory=dict)
    body_read_error: str | None = None
    body_read_detail: str = ""
    correlation_id: str | None = None
    matched_pattern_source: str | None = None
    queue_wait_seconds: float | None = None
    queue_wait_surface: str | None = None
