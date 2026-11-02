---

title: DetectionResult
description: API reference for the DetectionResult dataclass returned by guard-core's penetration detection helpers
keywords: detection result, penetration detection, threat categories, threat scores, guard-core
---

DetectionResult
===============

`DetectionResult` is the dataclass returned by `detect_penetration_attempt()` and `detect_penetration_patterns()`. Replaces the legacy `tuple[bool, str]` return so callers can read per-category metadata alongside the boolean verdict.

```python
from dataclasses import dataclass, field


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
```

___

Fields
------

| Field               | Type               | Description                                                                                                          |
|---------------------|--------------------|----------------------------------------------------------------------------------------------------------------------|
| `is_threat`         | `bool`             | `True` when at least one regex or semantic pattern matched.                                                          |
| `trigger_info`      | `str`              | Human-readable description of the first hit (e.g. `"Query param 'q': Value matched pattern '...'"`). Empty when `is_threat=False`. |
| `threat_categories` | `list[str]`        | Ordered list of categories that contributed at least one match (`"sqli"`, `"xss"`, `"custom"`, ...). Deduplicated; preserves first-seen order. |
| `threat_scores`     | `dict[str, float]` | Maximum score per category. Regex matches contribute `1.0`; semantic matches contribute their probability or threat score. |
| `body_read_error`   | `str \| None`      | `"stalled"` or `"failed"` when the request body could not be read, `"queue_wait"` when a scan got no regex worker in time (see `queue_wait_seconds` and `queue_wait_surface`); `None` otherwise. |
| `body_read_detail`  | `str`              | Sanitized detail for `body_read_error`. |
| `correlation_id`    | `str \| None`      | The random per-request id of the scan that produced the result (`uuid4`, no address or user data). The `penetration_attempt` event and the `pattern_detected` events of that request carry it as `correlation_id`. |
| `queue_wait_seconds` | `float \| None` | The wait that ended a scan with `body_read_error == "queue_wait"`, `None` otherwise. |
| `queue_wait_surface` | `str \| None` | What was being scanned when that wait ended: `"url path"`, `"query"`, `"header"` or `"body field"`; `None` otherwise. |
| `matched_pattern_source` | `str \| None` | Source text of the first regex pattern that matched, `None` when no regex matched. Used to attribute the event to a dynamic rule; it is never put in an event. |

___

When to inspect each field
--------------------------

`is_threat` is the gate. Most callers short-circuit on it and return early.

`threat_categories` is what you read when the next decision depends on which kind of attack you saw. Per-category ban policy uses it (`SecurityConfig.threat_ban_config`); dashboards use it to render the right glyph. The list is empty when only legacy semantic hits occurred without category labels.

`threat_scores` is what you read when you want a numeric handle for ranking, alerting, or dashboard severity. The values are not normalized across regex and semantic, regex always reports `1.0`, semantic reports its model probability.

___

Example
-------

```python
from guard_core.utils import detect_penetration_attempt


async def handle_submission(request, logger):
    result = await detect_penetration_attempt(request)
    if not result.is_threat:
        return {"ok": True}

    logger.warning(f"Detection: {result.trigger_info}")
    for category in result.threat_categories:
        score = result.threat_scores.get(category, 0.0)
        logger.warning(f"  category={category} score={score:.2f}")
    return {"error": "Suspicious activity detected"}
```

___

Migration from `tuple[bool, str]`
---------------------------------

```python
detected, trigger = await detect_penetration_attempt(request)

result = await detect_penetration_attempt(request)
detected, trigger = result.is_threat, result.trigger_info
```

The legacy 2-tuple is no longer returned. Callers that destructured the old tuple must migrate. See [Migration guide](../migration/v1-to-v2.md) for the full breaking-change list.
