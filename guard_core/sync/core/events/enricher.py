from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from guard_core.sync.core.events.event_types import (
    ENRICHMENT_KEY_BEHAVIOR_KEY,
    ENRICHMENT_KEY_DEPLOYMENT_ENV,
    ENRICHMENT_KEY_PROJECT_ID,
    ENRICHMENT_KEY_RECENT_EVENT_COUNT,
    ENRICHMENT_KEY_RULE_ID,
    ENRICHMENT_KEY_RULE_VERSION,
    ENRICHMENT_KEY_SERVICE_NAME,
    ENRICHMENT_KEY_THREAT_SCORE,
    EVENT_ACCESS_DENIED,
    EVENT_AUTHENTICATION_FAILED,
    EVENT_BEHAVIOR_VIOLATION,
    EVENT_CLOUD_BLOCKED,
    EVENT_CONTENT_FILTERED,
    EVENT_COUNTRY_BLOCKED,
    EVENT_CSP_VIOLATION,
    EVENT_CUSTOM_REQUEST_CHECK,
    EVENT_DECODING_ERROR,
    EVENT_DECORATOR_VIOLATION,
    EVENT_DETECTION_ENGINE_CALLBACK_ERROR,
    EVENT_DYNAMIC_RULE_APPLIED,
    EVENT_DYNAMIC_RULE_UPDATED,
    EVENT_DYNAMIC_RULE_VIOLATION,
    EVENT_EMERGENCY_MODE,
    EVENT_EMERGENCY_MODE_BLOCK,
    EVENT_GEO_LOOKUP_FAILED,
    EVENT_HTTPS_ENFORCED,
    EVENT_IP_BAN_FAILED,
    EVENT_IP_BANNED,
    EVENT_IP_BLOCKED,
    EVENT_IP_UNBANNED,
    EVENT_PATH_EXCLUDED,
    EVENT_PATTERN_ADDED,
    EVENT_PATTERN_ANOMALY_SLOW_EXECUTION,
    EVENT_PATTERN_ANOMALY_STATISTICAL_ANOMALY,
    EVENT_PATTERN_ANOMALY_TIMEOUT,
    EVENT_PATTERN_DETECTED,
    EVENT_PATTERN_REMOVED,
    EVENT_PENETRATION_ATTEMPT,
    EVENT_RATE_LIMIT_SCRIPT_RELOADED,
    EVENT_RATE_LIMITED,
    EVENT_REDIS_CONNECTION,
    EVENT_REDIS_ERROR,
    EVENT_ROUTE_UNRESOLVED,
    EVENT_SECURITY_BYPASS,
    EVENT_SECURITY_HEADERS_APPLIED,
    EVENT_SUSPICIOUS_REQUEST,
    EVENT_USER_AGENT_BLOCKED,
)
from guard_core.sync.handlers.behavior_handler import RECENT_REQUEST_WINDOW_SECONDS

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig

logger = logging.getLogger("guard_core.enricher")


_THREAT_SCORE_MAP: dict[str, int] = {
    EVENT_PENETRATION_ATTEMPT: 90,
    EVENT_IP_BANNED: 70,
    EVENT_EMERGENCY_MODE: 60,
    EVENT_IP_BLOCKED: 50,
    EVENT_BEHAVIOR_VIOLATION: 50,
    EVENT_CLOUD_BLOCKED: 50,
    EVENT_COUNTRY_BLOCKED: 50,
    EVENT_DECORATOR_VIOLATION: 50,
    EVENT_AUTHENTICATION_FAILED: 50,
    EVENT_EMERGENCY_MODE_BLOCK: 50,
    EVENT_DYNAMIC_RULE_VIOLATION: 50,
    EVENT_PATTERN_DETECTED: 50,
    EVENT_SUSPICIOUS_REQUEST: 50,
    EVENT_DYNAMIC_RULE_APPLIED: 40,
    EVENT_CSP_VIOLATION: 40,
    EVENT_CONTENT_FILTERED: 40,
    EVENT_CUSTOM_REQUEST_CHECK: 40,
    EVENT_DECODING_ERROR: 40,
    EVENT_REDIS_ERROR: 40,
    EVENT_IP_BAN_FAILED: 40,
    EVENT_DETECTION_ENGINE_CALLBACK_ERROR: 40,
    EVENT_PATTERN_ANOMALY_TIMEOUT: 40,
    EVENT_PATTERN_ANOMALY_SLOW_EXECUTION: 40,
    EVENT_PATTERN_ANOMALY_STATISTICAL_ANOMALY: 40,
    EVENT_ACCESS_DENIED: 30,
    EVENT_USER_AGENT_BLOCKED: 30,
    EVENT_SECURITY_BYPASS: 30,
    EVENT_RATE_LIMITED: 20,
    EVENT_GEO_LOOKUP_FAILED: 20,
    EVENT_REDIS_CONNECTION: 20,
    EVENT_ROUTE_UNRESOLVED: 20,
    EVENT_IP_UNBANNED: 10,
    EVENT_HTTPS_ENFORCED: 10,
    EVENT_DYNAMIC_RULE_UPDATED: 10,
    EVENT_PATH_EXCLUDED: 10,
    EVENT_PATTERN_ADDED: 10,
    EVENT_PATTERN_REMOVED: 10,
    EVENT_RATE_LIMIT_SCRIPT_RELOADED: 10,
    EVENT_SECURITY_HEADERS_APPLIED: 10,
}
_DEFAULT_THREAT_SCORE = 20

_BEHAVIOR_CORRELATION_WINDOW_SECONDS = RECENT_REQUEST_WINDOW_SECONDS


class ThreatScorer:
    @staticmethod
    def score_for(event_type: str) -> int:
        return _THREAT_SCORE_MAP.get(event_type, _DEFAULT_THREAT_SCORE)


@dataclass
class EnrichmentContext:
    config: SecurityConfig
    agent_handler: Any | None = None
    dynamic_rule_handler: Any | None = None
    behavior_tracker: Any | None = None


class EventEnricher:
    def __init__(self, context: EnrichmentContext) -> None:
        self._context = context

    def enrich_event(self, event: Any) -> None:
        try:
            metadata = getattr(event, "metadata", None)
            if metadata is None:
                return
            self._apply_identity(metadata)
            self._apply_threat_score(event, metadata)
            self._apply_rule_correlation(event, metadata)
            self._apply_behavior_correlation(event, metadata)
        except Exception:
            logger.exception("event enrichment failed; event will be sent unenriched")

    def enrich_metric(self, metric: Any) -> None:
        try:
            tags = getattr(metric, "tags", None)
            if tags is None:
                return
            self._apply_identity(tags)
        except Exception:
            logger.exception("metric enrichment failed; metric will be sent unenriched")

    def _apply_identity(self, bag: dict[str, Any]) -> None:
        cfg = self._context.config
        if cfg.agent_project_id:
            bag[ENRICHMENT_KEY_PROJECT_ID] = cfg.agent_project_id
        bag[ENRICHMENT_KEY_SERVICE_NAME] = cfg.otel_service_name
        env = cfg.otel_resource_attributes.get("deployment.environment")
        if env:
            bag[ENRICHMENT_KEY_DEPLOYMENT_ENV] = env

    def _apply_threat_score(self, event: Any, bag: dict[str, Any]) -> None:
        event_type = getattr(event, "event_type", None)
        if not event_type:
            return
        bag[ENRICHMENT_KEY_THREAT_SCORE] = ThreatScorer.score_for(event_type)

    def _apply_rule_correlation(self, event: Any, bag: dict[str, Any]) -> None:
        rule_handler = self._context.dynamic_rule_handler
        if rule_handler is None or not hasattr(rule_handler, "match_event"):
            return
        match = rule_handler.match_event(event)
        if match is None:
            return
        rule_id, rule_version = match
        bag[ENRICHMENT_KEY_RULE_ID] = rule_id
        bag[ENRICHMENT_KEY_RULE_VERSION] = rule_version

    def _apply_behavior_correlation(self, event: Any, bag: dict[str, Any]) -> None:
        tracker = self._context.behavior_tracker
        ip = getattr(event, "ip_address", None)
        if tracker is None or not ip:
            return
        if not hasattr(tracker, "get_recent_event_count"):
            return
        window_seconds = _BEHAVIOR_CORRELATION_WINDOW_SECONDS
        count = tracker.get_recent_event_count(ip, window_seconds)
        bag[ENRICHMENT_KEY_RECENT_EVENT_COUNT] = count
        bucket = int(time.time() // window_seconds)
        service = self._context.config.otel_service_name
        raw = f"{ip}|{service}|{bucket}".encode()
        bag[ENRICHMENT_KEY_BEHAVIOR_KEY] = hashlib.sha256(raw).hexdigest()[:16]
