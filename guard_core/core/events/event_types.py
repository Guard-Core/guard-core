from __future__ import annotations

from dataclasses import dataclass

EVENT_PENETRATION_ATTEMPT = "penetration_attempt"
EVENT_IP_BLOCKED = "ip_blocked"
EVENT_IP_BANNED = "ip_banned"
EVENT_IP_BAN_FAILED = "ip_ban_failed"
EVENT_IP_BAN_REFUSED = "ip_ban_refused"
EVENT_IP_UNBANNED = "ip_unbanned"
EVENT_CLOUD_BLOCKED = "cloud_blocked"
EVENT_HTTPS_ENFORCED = "https_enforced"
EVENT_DECORATOR_VIOLATION = "decorator_violation"
EVENT_BEHAVIOR_VIOLATION = "behavioral_violation"
EVENT_PATTERN_DETECTED = "pattern_detected"
EVENT_DYNAMIC_RULE_UPDATED = "dynamic_rule_updated"
EVENT_DYNAMIC_RULE_APPLIED = "dynamic_rule_applied"
EVENT_DYNAMIC_RULE_VIOLATION = "dynamic_rule_violation"
EVENT_EMERGENCY_MODE = "emergency_mode_activated"

EVENT_ACCESS_DENIED = "access_denied"
EVENT_AUTHENTICATION_FAILED = "authentication_failed"
EVENT_CONTENT_FILTERED = "content_filtered"
EVENT_COUNTRY_BLOCKED = "country_blocked"
EVENT_CSP_VIOLATION = "csp_violation"
EVENT_CUSTOM_REQUEST_CHECK = "custom_request_check"
EVENT_DECODING_ERROR = "decoding_error"
EVENT_EMERGENCY_MODE_BLOCK = "emergency_mode_block"
EVENT_GEO_LOOKUP_FAILED = "geo_lookup_failed"
EVENT_PATH_EXCLUDED = "path_excluded"
EVENT_PATTERN_ADDED = "pattern_added"
EVENT_PATTERN_REMOVED = "pattern_removed"
EVENT_RATE_LIMITED = "rate_limited"
EVENT_RATE_LIMIT_SCRIPT_RELOADED = "rate_limit_script_reloaded"
EVENT_REDIS_CONNECTION = "redis_connection"
EVENT_REDIS_ERROR = "redis_error"
EVENT_ROUTE_UNRESOLVED = "route_unresolved"
EVENT_SECURITY_BYPASS = "security_bypass"
EVENT_SECURITY_HEADERS_APPLIED = "security_headers_applied"
EVENT_USER_AGENT_BLOCKED = "user_agent_blocked"
EVENT_SUSPICIOUS_REQUEST = "suspicious_request"
EVENT_DETECTION_ENGINE_CALLBACK_ERROR = "detection_engine_callback_error"
EVENT_PATTERN_ANOMALY_TIMEOUT = "pattern_anomaly_timeout"
EVENT_PATTERN_ANOMALY_SLOW_EXECUTION = "pattern_anomaly_slow_execution"
EVENT_PATTERN_ANOMALY_STATISTICAL_ANOMALY = "pattern_anomaly_statistical_anomaly"

EVENT_TYPE_VALUES: frozenset[str] = frozenset(
    {
        EVENT_PENETRATION_ATTEMPT,
        EVENT_IP_BLOCKED,
        EVENT_IP_BANNED,
        EVENT_IP_BAN_FAILED,
        EVENT_IP_BAN_REFUSED,
        EVENT_IP_UNBANNED,
        EVENT_CLOUD_BLOCKED,
        EVENT_HTTPS_ENFORCED,
        EVENT_DECORATOR_VIOLATION,
        EVENT_BEHAVIOR_VIOLATION,
        EVENT_PATTERN_DETECTED,
        EVENT_DYNAMIC_RULE_UPDATED,
        EVENT_DYNAMIC_RULE_APPLIED,
        EVENT_DYNAMIC_RULE_VIOLATION,
        EVENT_EMERGENCY_MODE,
        EVENT_ACCESS_DENIED,
        EVENT_AUTHENTICATION_FAILED,
        EVENT_CONTENT_FILTERED,
        EVENT_COUNTRY_BLOCKED,
        EVENT_CSP_VIOLATION,
        EVENT_CUSTOM_REQUEST_CHECK,
        EVENT_DECODING_ERROR,
        EVENT_EMERGENCY_MODE_BLOCK,
        EVENT_GEO_LOOKUP_FAILED,
        EVENT_PATH_EXCLUDED,
        EVENT_PATTERN_ADDED,
        EVENT_PATTERN_REMOVED,
        EVENT_RATE_LIMITED,
        EVENT_RATE_LIMIT_SCRIPT_RELOADED,
        EVENT_REDIS_CONNECTION,
        EVENT_REDIS_ERROR,
        EVENT_ROUTE_UNRESOLVED,
        EVENT_SECURITY_BYPASS,
        EVENT_SECURITY_HEADERS_APPLIED,
        EVENT_USER_AGENT_BLOCKED,
        EVENT_SUSPICIOUS_REQUEST,
        EVENT_DETECTION_ENGINE_CALLBACK_ERROR,
        EVENT_PATTERN_ANOMALY_TIMEOUT,
        EVENT_PATTERN_ANOMALY_SLOW_EXECUTION,
        EVENT_PATTERN_ANOMALY_STATISTICAL_ANOMALY,
    }
)

METRIC_RESPONSE_TIME = "response_time"
METRIC_REQUEST_COUNT = "request_count"
METRIC_ERROR_RATE = "error_rate"

METRIC_TYPE_VALUES: frozenset[str] = frozenset(
    {
        METRIC_RESPONSE_TIME,
        METRIC_REQUEST_COUNT,
        METRIC_ERROR_RATE,
    }
)

CHECK_NAME_VALUES: frozenset[str] = frozenset(
    {
        "authentication",
        "cloud_ip_refresh",
        "cloud_provider",
        "custom_request",
        "custom_validators",
        "emergency_mode",
        "https_enforcement",
        "ip_security",
        "rate_limit",
        "referrer",
        "request_logging",
        "request_size_content",
        "required_headers",
        "route_config",
        "suspicious_activity",
        "time_window",
        "user_agent",
    }
)


ENRICHMENT_KEY_PROJECT_ID = "guard.project_id"
ENRICHMENT_KEY_SERVICE_NAME = "guard.service.name"
ENRICHMENT_KEY_DEPLOYMENT_ENV = "guard.deployment.environment"
ENRICHMENT_KEY_THREAT_SCORE = "guard.threat_score"
ENRICHMENT_KEY_RULE_ID = "guard.rule.id"
ENRICHMENT_KEY_RULE_VERSION = "guard.rule.version"
ENRICHMENT_KEY_BEHAVIOR_KEY = "guard.behavior.correlation_key"
ENRICHMENT_KEY_RECENT_EVENT_COUNT = "guard.behavior.recent_event_count"


@dataclass(frozen=True)
class EventFilter:
    muted_event_types: frozenset[str] = frozenset()
    muted_metric_types: frozenset[str] = frozenset()

    def is_event_allowed(self, event_type: str) -> bool:
        return event_type not in self.muted_event_types

    def is_metric_allowed(self, metric_type: str) -> bool:
        return metric_type not in self.muted_metric_types
