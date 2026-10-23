import re
import time
from functools import cache
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.events.middleware_events import SecurityEventBus
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.handlers.ratelimit_handler import (
    RateLimitManager,
    RateLimitTier,
    RateLimitVerdict,
)
from guard_core.sync.handlers.security_headers_handler import SecurityHeadersManager
from guard_core.sync.handlers.suspatterns_handler import (
    SusPatternsManager,
    sus_patterns_handler,
)
from guard_core.sync.utils import _check_value_enhanced

_REFERENCE_WORKLOAD_SECONDS = 0.1243


@cache
def _host_cpu_speed_factor() -> float:
    samples: list[float] = []
    for _ in range(3):
        start = time.process_time()
        total = 0
        for i in range(3_000_000):
            total += i * i
        samples.append(time.process_time() - start)
    return max(1.0, min(samples) / _REFERENCE_WORKLOAD_SECONDS)


def test_send_rule_received_event_no_agent() -> None:
    from datetime import datetime, timezone

    config = SyncSecurityConfig()
    config.enable_dynamic_rules = False
    manager = DynamicRuleManager(config)
    manager.agent_handler = None

    from guard_core.models import DynamicRules

    rules = DynamicRules(
        rule_id="test", version=1, timestamp=datetime.now(timezone.utc)
    )

    manager._send_rule_received_event(rules)

    assert True


def test_tier_verdict_without_a_redis_handler_counts_in_memory() -> None:
    config = SyncSecurityConfig()
    config.enable_redis = False
    manager = RateLimitManager(config)
    manager.redis_handler = None

    result = manager._tier_verdict(
        "127.0.0.1", [RateLimitTier("global", 10, 60)], config
    )

    assert result == RateLimitVerdict(None)
    assert len(manager.request_timestamps) == 1


def test_get_validated_cors_config_no_cors_config() -> None:
    manager = SecurityHeadersManager()
    manager.cors_config = None

    allow_methods, allow_headers = manager._get_validated_cors_config()

    assert allow_methods == ["GET", "POST"]
    assert allow_headers == ["*"]


def test_remove_default_pattern_not_found() -> None:
    handler = SusPatternsManager()

    original_patterns = handler.patterns.copy()
    original_compiled = handler.compiled_patterns.copy()

    try:
        result = handler._remove_default_pattern("nonexistent_pattern_xyz")

        assert result is False
    finally:
        handler.patterns = original_patterns
        handler.compiled_patterns = original_compiled


def test_remove_default_pattern_invalid_index() -> None:
    handler = SusPatternsManager()

    original_patterns = handler.patterns.copy()
    original_compiled = handler.compiled_patterns.copy()

    try:
        test_pattern = "test_pattern_xyz_123_unique_edge"
        handler.patterns.append(test_pattern)
        compiled = re.compile(test_pattern)
        handler.compiled_patterns.append((compiled, frozenset(), ""))

        handler.compiled_patterns = []

        result = handler._remove_default_pattern(test_pattern)

        assert result is False
    finally:
        handler.patterns = original_patterns
        handler.compiled_patterns = original_compiled


def test_fallback_pattern_check_recursion_error_is_logged_and_skipped(
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    from guard_core.sync.utils import _fallback_pattern_check

    with patch(
        "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_handler:
        mock_pattern = Mock()
        mock_pattern.pattern = "(evil){1,100}"
        mock_handler.get_all_compiled_patterns = MagicMock(
            return_value=[(mock_pattern, frozenset({"unknown"}), "custom")]
        )
        mock_handler._check_regex_pattern = MagicMock(
            side_effect=RecursionError("maximum recursion depth")
        )

        with caplog.at_level(logging.WARNING, logger="guard_core"):
            result = _fallback_pattern_check("test_value", "127.0.0.1", "unknown")

        assert result == (False, "")
        assert "recursion" in caplog.text.lower()
        assert "(evil){1,100}" in caplog.text


def test_fallback_pattern_check_unexpected_exception_propagates() -> None:
    from guard_core.sync.utils import _fallback_pattern_check

    with patch(
        "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_handler:
        mock_pattern = Mock()
        mock_pattern.pattern = "test_pattern"
        mock_handler.get_all_compiled_patterns = MagicMock(
            return_value=[(mock_pattern, frozenset({"unknown"}), "custom")]
        )
        mock_handler._check_regex_pattern = MagicMock(
            side_effect=ValueError("not a recursion error")
        )

        try:
            _fallback_pattern_check("test_value", "127.0.0.1", "unknown")
        except ValueError as exc:
            assert str(exc) == "not a recursion error"
        else:
            raise AssertionError("expected ValueError to propagate")


def _raising_detect(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
    raise RuntimeError("Detection engine failure")


def _raising_recursion_error_detect(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
    raise RecursionError("maximum recursion depth exceeded")


def test_check_value_enhanced_recursion_error_escapes_the_fallback() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())

    with patch.object(
        sus_patterns_handler, "detect", side_effect=_raising_recursion_error_detect
    ):
        with pytest.raises(RecursionError):
            _check_value_enhanced("' OR '1'='1", "request_body", "127.0.0.1", "corr-4")


_FALLBACK_SCAN_CPU_BUDGET_SECONDS = 0.05


def test_check_value_enhanced_fallback_scan_stays_cpu_bounded() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())
    value = "{{" * 10000

    with patch.object(sus_patterns_handler, "detect", side_effect=_raising_detect):
        samples: list[float] = []
        for _ in range(5):
            start = time.process_time()
            _check_value_enhanced(value, "request_body", "127.0.0.1", "corr-1")
            samples.append(time.process_time() - start)

    budget_seconds = _FALLBACK_SCAN_CPU_BUDGET_SECONDS * _host_cpu_speed_factor()
    assert min(samples) < budget_seconds, (
        "fallback pattern scan regressed: min of 5 runs against '{{' * 10000 took "
        f"{min(samples):.4f}s, budget={budget_seconds:.4f}s (base "
        f"{_FALLBACK_SCAN_CPU_BUDGET_SECONDS}s scaled by this host's "
        "_host_cpu_speed_factor())"
    )


def test_check_value_enhanced_fallback_scan_still_detects_sqli() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())

    with patch.object(sus_patterns_handler, "detect", side_effect=_raising_detect):
        detected, trigger, threats, log_override = _check_value_enhanced(
            "' OR '1'='1", "request_body", "127.0.0.1", "corr-2"
        )

    assert detected is True
    assert trigger != ""
    assert log_override is None


def test_check_value_enhanced_empty_threats_list() -> None:
    from guard_core.sync.utils import _check_value_enhanced

    with patch(
        "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_handler:
        mock_handler.detect = MagicMock(return_value={"is_threat": True, "threats": []})

        result = _check_value_enhanced(
            value="test_value",
            context="test_context",
            client_ip="127.0.0.1",
            correlation_id="test-123",
        )

        assert result == (True, "Threat detected", [], None)


def test_detect_penetration_attempt_real_path() -> None:
    from guard_core.sync.detection_result import DetectionResult
    from guard_core.sync.utils import detect_penetration_attempt

    mock_request = Mock()
    mock_request.client_host = "127.0.0.1"
    mock_request.query_params = {}
    mock_request.url_path = "/test"
    mock_request.headers = {}
    mock_request.body = MagicMock(return_value=b"")

    result = detect_penetration_attempt(mock_request)

    assert isinstance(result, DetectionResult)
    assert isinstance(result.is_threat, bool)
    assert isinstance(result.trigger_info, str)


def test_send_middleware_event_with_geo_ip_exception() -> None:
    config = SyncSecurityConfig()
    config.agent_enable_events = True

    mock_agent = Mock()
    mock_agent.send_event = MagicMock()

    mock_geo_ip = Mock()
    geo_exception = Exception("GeoIP failure")
    mock_geo_ip.get_country = Mock(side_effect=geo_exception)

    event_bus = SecurityEventBus(mock_agent, config, mock_geo_ip)

    mock_request = Mock()
    mock_request.client_host = "192.168.1.1"
    mock_request.state.client_ip = None
    mock_request.url_path = "/test"
    mock_request.method = "GET"
    mock_request.headers = {"User-Agent": "TestAgent"}

    event_bus.send_middleware_event(
        event_type="suspicious_request",
        request=mock_request,
        action_taken="logged",
        reason="test reason",
    )

    assert mock_agent.send_event.call_count == 1


def test_integration_all_edge_cases() -> None:
    from datetime import datetime, timezone

    config = SyncSecurityConfig()
    config.enable_redis = False
    config.enable_agent = False
    config.enable_dynamic_rules = False

    drm = DynamicRuleManager(config)
    from guard_core.models import DynamicRules

    rules = DynamicRules(
        rule_id="test", version=1, timestamp=datetime.now(timezone.utc)
    )
    drm._send_rule_received_event(rules)

    rlm = RateLimitManager(config)
    verdict = rlm._tier_verdict("127.0.0.1", [RateLimitTier("global", 10, 60)], config)
    assert verdict == RateLimitVerdict(None)

    shm = SecurityHeadersManager()
    shm.cors_config = None
    methods, headers = shm._get_validated_cors_config()
    assert methods == ["GET", "POST"]
    assert headers == ["*"]

    spm = SusPatternsManager()
    result = spm._remove_default_pattern("nonexistent")
    assert result is False
