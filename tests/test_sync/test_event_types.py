from guard_core.sync.core.events.event_types import (
    EVENT_ACCESS_DENIED,
    EVENT_AUTHENTICATION_FAILED,
    EVENT_BEHAVIOR_BUCKET_EVICTED,
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
    EVENT_IP_BAN_EVICTED,
    EVENT_IP_BAN_FAILED,
    EVENT_IP_BAN_REFUSED,
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
    EVENT_TYPE_VALUES,
    EVENT_USER_AGENT_BLOCKED,
    METRIC_ERROR_RATE,
    METRIC_REQUEST_COUNT,
    METRIC_RESPONSE_TIME,
    METRIC_TYPE_VALUES,
    EventFilter,
)


def test_event_type_constants_are_strings() -> None:
    for name in [
        "EVENT_PENETRATION_ATTEMPT",
        "EVENT_IP_BLOCKED",
        "EVENT_IP_BANNED",
        "EVENT_IP_UNBANNED",
        "EVENT_CLOUD_BLOCKED",
        "EVENT_HTTPS_ENFORCED",
        "EVENT_DECORATOR_VIOLATION",
        "EVENT_BEHAVIOR_VIOLATION",
        "EVENT_PATTERN_DETECTED",
        "EVENT_DYNAMIC_RULE_UPDATED",
        "EVENT_DYNAMIC_RULE_APPLIED",
        "EVENT_EMERGENCY_MODE",
    ]:
        val = globals().get(name)
        assert isinstance(val, str)


def test_event_type_values_contains_all() -> None:
    expected = {
        EVENT_PENETRATION_ATTEMPT,
        EVENT_IP_BLOCKED,
        EVENT_IP_BANNED,
        EVENT_IP_BAN_FAILED,
        EVENT_IP_BAN_REFUSED,
        EVENT_IP_BAN_EVICTED,
        EVENT_BEHAVIOR_BUCKET_EVICTED,
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
        EVENT_RATE_LIMIT_SCRIPT_RELOADED,
        EVENT_RATE_LIMITED,
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
    assert EVENT_TYPE_VALUES == expected


def test_metric_type_constants() -> None:
    assert METRIC_RESPONSE_TIME == "response_time"
    assert METRIC_REQUEST_COUNT == "request_count"
    assert METRIC_ERROR_RATE == "error_rate"


def test_metric_type_values_contains_all() -> None:
    assert METRIC_TYPE_VALUES == {
        METRIC_RESPONSE_TIME,
        METRIC_REQUEST_COUNT,
        METRIC_ERROR_RATE,
    }


def test_event_filter_allows_when_not_muted() -> None:
    filt = EventFilter(muted_event_types=frozenset(), muted_metric_types=frozenset())
    assert filt.is_event_allowed(EVENT_PENETRATION_ATTEMPT) is True
    assert filt.is_metric_allowed(METRIC_RESPONSE_TIME) is True


def test_event_filter_mutes_specific_events() -> None:
    filt = EventFilter(
        muted_event_types=frozenset({EVENT_CLOUD_BLOCKED, EVENT_HTTPS_ENFORCED}),
        muted_metric_types=frozenset(),
    )
    assert filt.is_event_allowed(EVENT_PENETRATION_ATTEMPT) is True
    assert filt.is_event_allowed(EVENT_CLOUD_BLOCKED) is False
    assert filt.is_event_allowed(EVENT_HTTPS_ENFORCED) is False


def test_event_filter_mutes_specific_metrics() -> None:
    filt = EventFilter(
        muted_event_types=frozenset(),
        muted_metric_types=frozenset({METRIC_RESPONSE_TIME}),
    )
    assert filt.is_metric_allowed(METRIC_RESPONSE_TIME) is False
    assert filt.is_metric_allowed(METRIC_REQUEST_COUNT) is True


def test_event_filter_defaults() -> None:
    filt = EventFilter()
    assert filt.muted_event_types == frozenset()
    assert filt.muted_metric_types == frozenset()
