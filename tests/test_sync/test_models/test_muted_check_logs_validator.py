import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.events.event_types import CHECK_NAME_VALUES


def test_check_name_values_contains_expected() -> None:
    expected = {
        "authentication",
        "cloud_ip_refresh",
        "cloud_provider",
        "cors_preflight",
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
    assert CHECK_NAME_VALUES == frozenset(expected)


def test_muted_check_logs_default_empty() -> None:
    assert SecurityConfig().muted_check_logs == set()


def test_muted_check_logs_accepts_known_names() -> None:
    config = SecurityConfig(muted_check_logs={"authentication", "rate_limit"})
    assert config.muted_check_logs == {"authentication", "rate_limit"}


def test_muted_check_logs_rejects_unknown_with_listing() -> None:
    with pytest.raises(ValueError) as exc:
        SecurityConfig(muted_check_logs={"suspcious_activity"})
    msg = str(exc.value)
    assert "suspcious_activity" in msg
    assert "authentication" in msg


def test_muted_event_types_error_lists_valid_values() -> None:
    with pytest.raises(ValueError) as exc:
        SecurityConfig(muted_event_types={"not_a_real_event"})
    msg = str(exc.value)
    assert "not_a_real_event" in msg
    assert "penetration_attempt" in msg


def test_muted_metric_types_error_lists_valid_values() -> None:
    with pytest.raises(ValueError) as exc:
        SecurityConfig(muted_metric_types={"not_a_real_metric"})
    msg = str(exc.value)
    assert "not_a_real_metric" in msg
    assert "response_time" in msg
