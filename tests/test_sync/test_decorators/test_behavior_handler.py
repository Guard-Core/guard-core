import logging
import time
from typing import Any, Literal, cast
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.handlers import behavior_handler
from guard_core.sync.handlers.behavior_handler import (
    BehaviorRule,
    BehaviorTracker,
    _hash_identity_segment,
)
from guard_core.sync.handlers.redis_handler import redis_handler
from tests.test_sync.conftest import MockGuardResponse


class _BoundedReaderResponse:
    def __init__(self, body: bytes, status_code: int = 200) -> None:
        self._status_code = status_code
        self._headers: dict[str, str] = {}
        self._body = body
        self.read_body_prefix_calls = 0
        self.body_property_accessed = False

    @property
    def status_code(self) -> int:
        return self._status_code

    @property
    def headers(self) -> dict[str, str]:
        return self._headers

    @property
    def body(self) -> bytes:
        self.body_property_accessed = True
        return self._body

    def read_body_prefix(self, max_bytes: int) -> bytes:
        self.read_body_prefix_calls += 1
        return self._body[:max_bytes]


def _rule_bucket(rule: BehaviorRule, endpoint_id: str) -> str:
    return f"{rule.discriminator()}|{endpoint_id}"


def test_behavior_rule_creation() -> None:
    rule = BehaviorRule(
        rule_type="usage",
        threshold=10,
    )
    assert rule.rule_type == "usage"
    assert rule.threshold == 10
    assert rule.window == 3600
    assert rule.pattern is None
    assert rule.action == "log"
    assert rule.custom_action is None

    custom_action = MagicMock()
    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=5,
        window=1800,
        pattern="json:status==success",
        action="ban",
        custom_action=custom_action,
    )
    assert rule.rule_type == "return_pattern"
    assert rule.threshold == 5
    assert rule.window == 1800
    assert rule.pattern == "json:status==success"
    assert rule.action == "ban"
    assert rule.custom_action == custom_action


@pytest.mark.parametrize(
    "rule_type,threshold,window,pattern,action",
    [
        ("usage", 10, 3600, None, "log"),
        ("return_pattern", 5, 1800, "status:200", "ban"),
        ("frequency", 20, 300, "regex:error", "throttle"),
    ],
)
def test_behavior_rule_parameterized(
    rule_type: Literal["usage", "return_pattern", "frequency"],
    threshold: int,
    window: int,
    pattern: str | None,
    action: Literal["ban", "log", "throttle", "alert"],
) -> None:
    rule = BehaviorRule(
        rule_type=rule_type,
        threshold=threshold,
        window=window,
        pattern=pattern,
        action=action,
    )
    assert rule.rule_type == rule_type
    assert rule.threshold == threshold
    assert rule.window == window
    assert rule.pattern == pattern
    assert rule.action == action


def test_behavior_tracker_initialization(security_config: SecurityConfig) -> None:
    tracker = BehaviorTracker(security_config)
    assert tracker.config == security_config
    assert tracker.logger is not None
    assert tracker.usage_counts is not None
    assert tracker.return_patterns is not None
    assert tracker.redis_handler is None


def test_initialize_redis(security_config_redis: SecurityConfig) -> None:
    tracker = BehaviorTracker(security_config_redis)
    redis_mgr = redis_handler(security_config_redis)
    redis_mgr.initialize()

    tracker.initialize_redis(redis_mgr)
    assert tracker.redis_handler == redis_mgr

    redis_mgr.close()


def test_track_endpoint_usage_in_memory(security_config: SecurityConfig) -> None:
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=3, window=1)

    endpoint_id = "/api/test"
    client_ip = "192.168.1.1"

    assert not tracker.track_endpoint_usage(endpoint_id, client_ip, rule)
    assert not tracker.track_endpoint_usage(endpoint_id, client_ip, rule)
    assert not tracker.track_endpoint_usage(endpoint_id, client_ip, rule)

    assert tracker.track_endpoint_usage(endpoint_id, client_ip, rule)

    assert len(tracker.usage_counts[_rule_bucket(rule, endpoint_id)][client_ip]) == 4


def test_track_endpoint_usage_with_window_cleanup(
    security_config: SecurityConfig,
) -> None:
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=2, window=1)

    endpoint_id = "/api/test"
    client_ip = "192.168.1.1"

    current_time = time.time()
    old_time = current_time - 2
    bucket_key = _rule_bucket(rule, endpoint_id)
    tracker.usage_counts[bucket_key][client_ip].append(old_time)
    tracker.usage_counts[bucket_key][client_ip].append(old_time)

    assert not tracker.track_endpoint_usage(endpoint_id, client_ip, rule)

    assert len(tracker.usage_counts[bucket_key][client_ip]) == 1


def test_track_endpoint_usage_evicts_the_oldest_client_a_touched_client_survives(
    security_config: SecurityConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(behavior_handler, "_MAX_TRACKED_CLIENTS_PER_ENDPOINT", 3)
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=999, window=60)
    endpoint_id = "/api/test"

    for client_ip in ("203.0.113.1", "203.0.113.2", "203.0.113.3"):
        tracker.track_endpoint_usage(endpoint_id, client_ip, rule)

    tracker.track_endpoint_usage(endpoint_id, "203.0.113.1", rule)
    tracker.track_endpoint_usage(endpoint_id, "203.0.113.4", rule)

    bucket = tracker.usage_counts[_rule_bucket(rule, endpoint_id)]
    assert len(bucket) == 3
    assert "203.0.113.2" not in bucket
    assert "203.0.113.1" in bucket
    assert "203.0.113.4" in bucket


def test_track_endpoint_usage_evicts_oldest_endpoint_touched_one_survives(
    security_config: SecurityConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(behavior_handler, "_MAX_TRACKED_ENDPOINTS", 3)
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=999, window=60)
    client_ip = "203.0.113.1"

    for endpoint_id in ("/api/one", "/api/two", "/api/three"):
        tracker.track_endpoint_usage(endpoint_id, client_ip, rule)

    tracker.track_endpoint_usage("/api/one", client_ip, rule)
    tracker.track_endpoint_usage("/api/four", client_ip, rule)

    assert len(tracker.usage_counts) == 3
    assert _rule_bucket(rule, "/api/two") not in tracker.usage_counts
    assert _rule_bucket(rule, "/api/one") in tracker.usage_counts
    assert _rule_bucket(rule, "/api/four") in tracker.usage_counts


def test_track_endpoint_usage_many_endpoints_settle_at_default_bound(
    security_config: SecurityConfig,
) -> None:
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=999, window=60)
    client_ip = "203.0.113.1"

    for i in range(15_000):
        tracker.track_endpoint_usage(f"/api/endpoint-{i}", client_ip, rule)

    assert len(tracker.usage_counts) == 10_000
    assert _rule_bucket(rule, "/api/endpoint-0") not in tracker.usage_counts
    assert _rule_bucket(rule, "/api/endpoint-14999") in tracker.usage_counts


def test_track_endpoint_usage_with_redis(
    security_config_redis: SecurityConfig,
) -> None:
    tracker = BehaviorTracker(security_config_redis)
    redis_mgr = redis_handler(security_config_redis)
    redis_mgr.initialize()
    tracker.initialize_redis(redis_mgr)

    rule = BehaviorRule(rule_type="usage", threshold=2, window=60)
    endpoint_id = "/api/test"
    client_ip = "192.168.1.1"

    with patch.object(redis_mgr, "record_sliding_window_hit") as mock_record:
        mock_record.return_value = 1
        result = tracker.track_endpoint_usage(endpoint_id, client_ip, rule)
        assert not result

        mock_record.return_value = 2
        result = tracker.track_endpoint_usage(endpoint_id, client_ip, rule)
        assert not result

        mock_record.return_value = 3
        result = tracker.track_endpoint_usage(endpoint_id, client_ip, rule)
        assert result

    redis_mgr.close()


def test_track_endpoint_usage_redis_key_uses_hashed_segments(
    security_config_redis: SecurityConfig,
) -> None:
    tracker = BehaviorTracker(security_config_redis)
    redis_mgr = redis_handler(security_config_redis)
    redis_mgr.initialize()
    tracker.initialize_redis(redis_mgr)

    rule = BehaviorRule(rule_type="usage", threshold=5, window=60)
    endpoint_id = "/api/test"
    client_ip = "192.168.1.1"

    with patch.object(redis_mgr, "record_sliding_window_hit") as mock_record:
        mock_record.return_value = 1
        tracker.track_endpoint_usage(endpoint_id, client_ip, rule)

    namespace, key = mock_record.call_args.args[0], mock_record.call_args.args[1]
    assert namespace == "behavior_usage"
    assert endpoint_id not in key
    assert client_ip not in key
    assert key == (
        f"behavior:usage:{_hash_identity_segment(endpoint_id)}:"
        f"{_hash_identity_segment(client_ip)}:"
        f"{_hash_identity_segment(rule.discriminator())}"
    )

    redis_mgr.close()


def test_track_return_pattern_no_pattern(security_config: SecurityConfig) -> None:
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="return_pattern", threshold=5)

    response = MockGuardResponse("test", status_code=200)
    result = tracker.track_return_pattern("/api/test", "192.168.1.1", response, rule)
    assert not result


def test_track_return_pattern_in_memory(security_config: SecurityConfig) -> None:
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="return_pattern", threshold=2, pattern="status:200")

    endpoint_id = "/api/test"
    client_ip = "192.168.1.1"
    response = MockGuardResponse("success", status_code=200)

    assert not tracker.track_return_pattern(endpoint_id, client_ip, response, rule)
    assert not tracker.track_return_pattern(endpoint_id, client_ip, response, rule)

    assert tracker.track_return_pattern(endpoint_id, client_ip, response, rule)


def test_track_return_pattern_with_redis(
    security_config_redis: SecurityConfig,
) -> None:
    tracker = BehaviorTracker(security_config_redis)
    redis_mgr = redis_handler(security_config_redis)
    redis_mgr.initialize()
    tracker.initialize_redis(redis_mgr)

    rule = BehaviorRule(rule_type="return_pattern", threshold=1, pattern="status:200")
    response = MockGuardResponse("success", status_code=200)

    with patch.object(redis_mgr, "record_sliding_window_hit") as mock_record:
        mock_record.return_value = 2

        result = tracker.track_return_pattern(
            "/api/test", "192.168.1.1", response, rule
        )
        assert result

    redis_mgr.close()


def test_track_return_pattern_redis_key_uses_hashed_segments(
    security_config_redis: SecurityConfig,
) -> None:
    tracker = BehaviorTracker(security_config_redis)
    redis_mgr = redis_handler(security_config_redis)
    redis_mgr.initialize()
    tracker.initialize_redis(redis_mgr)

    rule = BehaviorRule(rule_type="return_pattern", threshold=5, pattern="status:200")
    response = MockGuardResponse("success", status_code=200)
    endpoint_id = "/api/test"
    client_ip = "192.168.1.1"

    with patch.object(redis_mgr, "record_sliding_window_hit") as mock_record:
        mock_record.return_value = 1
        tracker.track_return_pattern(endpoint_id, client_ip, response, rule)

    namespace, key = mock_record.call_args.args[0], mock_record.call_args.args[1]
    assert namespace == "behavior_returns"
    assert endpoint_id not in key
    assert client_ip not in key
    assert rule.pattern is not None
    assert rule.pattern not in key
    assert key == (
        f"behavior:return:{_hash_identity_segment(endpoint_id)}:"
        f"{_hash_identity_segment(client_ip)}:"
        f"{_hash_identity_segment(rule.discriminator())}"
    )

    redis_mgr.close()


@pytest.mark.parametrize(
    "status_code,pattern,expected",
    [
        (200, "status:200", True),
        (404, "status:200", False),
    ],
)
def test_check_response_pattern(
    security_config: SecurityConfig,
    status_code: int,
    pattern: str,
    expected: bool,
) -> None:
    tracker = BehaviorTracker(security_config)

    response = MockGuardResponse("", status_code=status_code)

    result = tracker._check_response_pattern(response, pattern)
    assert result == expected


def test_check_response_pattern_json_invalid(
    security_config: SecurityConfig,
) -> None:
    security_config.behavior_scan_response_body = True
    tracker = BehaviorTracker(security_config)
    response = _BoundedReaderResponse(b"invalid json {", status_code=200)

    result = tracker._check_response_pattern(response, "json:status==success")
    assert result is False


def test_check_response_pattern_no_body_when_body_scan_disabled(
    security_config: SecurityConfig,
) -> None:
    tracker = BehaviorTracker(security_config)
    response = _BoundedReaderResponse(b"test pattern", status_code=200)

    result = tracker._check_response_pattern(response, "test pattern")

    assert result is None
    assert response.read_body_prefix_calls == 0


def test_check_response_pattern_empty_body_is_not_matched(
    security_config: SecurityConfig,
) -> None:
    security_config.behavior_scan_response_body = True
    tracker = BehaviorTracker(security_config)
    response = _BoundedReaderResponse(b"", status_code=200)

    result = tracker._check_response_pattern(response, "test pattern")
    assert result is False


class _StreamingResponseWithoutBody:
    def __init__(self, status_code: int = 200) -> None:
        self.status_code = status_code


def test_check_response_pattern_missing_bounded_reader_logs_once(
    security_config: SecurityConfig,
) -> None:
    security_config.behavior_scan_response_body = True
    tracker = BehaviorTracker(security_config)
    response = cast(GuardResponse, _StreamingResponseWithoutBody())

    with patch.object(tracker.logger, "warning") as mock_warning:
        for _ in range(5):
            result = tracker._check_response_pattern(response, "attack-marker")

    assert result is None
    mock_warning.assert_called_once()
    assert "attack-marker" in mock_warning.call_args.args
    assert "could not be evaluated" in mock_warning.call_args.args[0]


def test_check_response_pattern_missing_bounded_reader_logs_per_pattern(
    security_config: SecurityConfig,
) -> None:
    security_config.behavior_scan_response_body = True
    tracker = BehaviorTracker(security_config)
    response = cast(GuardResponse, _StreamingResponseWithoutBody())

    with patch.object(tracker.logger, "warning") as mock_warning:
        tracker._check_response_pattern(response, "pattern-one")
        tracker._check_response_pattern(response, "pattern-two")

    assert mock_warning.call_count == 2


def test_check_response_pattern_bytes_body(
    security_config: SecurityConfig,
) -> None:
    security_config.behavior_scan_response_body = True
    tracker = BehaviorTracker(security_config)
    response = _BoundedReaderResponse(b"test content", status_code=200)

    result = tracker._check_response_pattern(response, "test content")
    assert result is True
    assert response.read_body_prefix_calls == 1


def test_check_response_pattern_json_match_via_bounded_reader(
    security_config: SecurityConfig,
) -> None:
    security_config.behavior_scan_response_body = True
    tracker = BehaviorTracker(security_config)
    response = _BoundedReaderResponse(b'{"status": "success"}', status_code=200)

    result = tracker._check_response_pattern(response, "json:status==success")
    assert result is True


def test_check_response_pattern_regex_match_via_bounded_reader(
    security_config: SecurityConfig,
) -> None:
    security_config.behavior_scan_response_body = True
    tracker = BehaviorTracker(security_config)
    response = _BoundedReaderResponse(
        b"Error: Database connection failed", status_code=500
    )

    result = tracker._check_response_pattern(response, "regex:database.*failed")
    assert result is True


def test_check_response_pattern_never_reads_body_property(
    security_config: SecurityConfig,
) -> None:
    security_config.behavior_scan_response_body = True
    tracker = BehaviorTracker(security_config)
    response = _BoundedReaderResponse(b"test content", status_code=200)

    tracker._check_response_pattern(response, "test content")

    assert response.body_property_accessed is False


def test_check_response_pattern_exception(
    security_config: SecurityConfig,
) -> None:
    security_config.behavior_scan_response_body = True
    tracker = BehaviorTracker(security_config)

    with patch.object(tracker.logger, "error") as mock_logger:
        response = _BoundedReaderResponse(b"test", status_code=200)

        with patch("json.loads", side_effect=Exception("Test error")):
            result = tracker._check_response_pattern(response, "json:test==value")
            assert result is False
            mock_logger.assert_called_once()


def test_check_response_pattern_non_bytes_prefix_is_logged_and_not_matched(
    security_config: SecurityConfig,
    caplog: pytest.LogCaptureFixture,
) -> None:
    security_config.behavior_scan_response_body = True
    tracker = BehaviorTracker(security_config)

    class _StringReturningReader:
        status_code = 200
        headers: dict[str, str] = {}

        def read_body_prefix(self, max_bytes: int) -> bytes:
            return cast(bytes, "not bytes")

    response = cast(GuardResponse, _StringReturningReader())

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = tracker._check_response_pattern(response, "12345")

    assert result is None
    assert "return_pattern rule with pattern '12345' could not be evaluated" in (
        caplog.text
    )


def test_check_response_pattern_raising_bounded_reader_is_could_not_evaluate(
    security_config: SecurityConfig,
) -> None:
    security_config.behavior_scan_response_body = True
    tracker = BehaviorTracker(security_config)

    class _RaisingReader:
        status_code = 200
        headers: dict[str, str] = {}

        def read_body_prefix(self, max_bytes: int) -> bytes:
            raise RuntimeError("stream closed")

    response = cast(GuardResponse, _RaisingReader())

    result = tracker._check_response_pattern(response, "attack")
    assert result is None


def test_check_response_pattern_oversized_prefix_is_capped(
    security_config: SecurityConfig,
) -> None:
    security_config.behavior_scan_response_body = True
    security_config.behavior_max_response_body_inspect_bytes = 1024

    class _OverReportingReader:
        status_code = 200
        headers: dict[str, str] = {}

        def __init__(self) -> None:
            self.requested_max_bytes: int | None = None

        def read_body_prefix(self, max_bytes: int) -> bytes:
            self.requested_max_bytes = max_bytes
            return b"A" * 2000 + b"MARKER"

    tracker = BehaviorTracker(security_config)
    response = _OverReportingReader()

    result = tracker._check_response_pattern(cast(GuardResponse, response), "MARKER")

    assert result is False
    assert response.requested_max_bytes == 1024


def test_match_json_pattern_exception(security_config: SecurityConfig) -> None:
    tracker = BehaviorTracker(security_config)

    class ProblematicData:
        def __str__(self) -> str:
            raise Exception("Test exception in str conversion")

    problematic_data = {"nested": {"value": ProblematicData()}}

    result = tracker._match_json_pattern(problematic_data, "nested.value==test")
    assert not result


@pytest.mark.parametrize(
    "data,pattern,expected",
    [
        ({"status": "success"}, "status==success", True),
        ({"status": "error"}, "status==success", False),
        ({"result": {"status": "win"}}, "result.status==win", True),
        ({"result": {"status": "lose"}}, "result.status==win", False),
        ({"items": ["rare", "common"]}, "items[]==rare", True),
        ({"items": ["common", "uncommon"]}, "items[]==rare", False),
        ({"other": "value"}, "status==success", False),
        ({"result": {}}, "result.status==win", False),
    ],
)
def test_match_json_pattern(
    security_config: SecurityConfig, data: dict[str, Any], pattern: str, expected: bool
) -> None:
    tracker = BehaviorTracker(security_config)
    result = tracker._match_json_pattern(data, pattern)
    assert result == expected


def test_match_json_pattern_invalid(security_config: SecurityConfig) -> None:
    tracker = BehaviorTracker(security_config)

    result = tracker._match_json_pattern({"status": "success"}, "status")
    assert not result

    result = tracker._match_json_pattern(
        {"status": "success"}, "invalid..pattern==test"
    )
    assert not result


def test_apply_action_custom(security_config: SecurityConfig) -> None:
    tracker = BehaviorTracker(security_config)
    custom_action = MagicMock()
    rule = BehaviorRule(rule_type="usage", threshold=5, custom_action=custom_action)

    tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")
    custom_action.assert_called_once_with("192.168.1.1", "/api/test", "Test violation")


def test_apply_action_ban(security_config: SecurityConfig) -> None:
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=5, action="ban")

    with (
        patch(
            "guard_core.sync.handlers.ipban_handler.ip_ban_manager"
        ) as mock_ban_manager,
        patch.object(tracker.logger, "warning") as mock_logger,
    ):
        mock_ban_manager._ban_ip_escalating = MagicMock()

        tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")

        mock_ban_manager._ban_ip_escalating.assert_called_once_with(
            "192.168.1.1", 3600, "behavioral_violation", grouped=False
        )
        mock_logger.assert_called_once()


def test_apply_action_log(security_config: SecurityConfig) -> None:
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=5, action="log")

    with patch.object(tracker.logger, "warning") as mock_logger:
        tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")
        mock_logger.assert_called_once_with(
            "Behavioral anomaly detected: Test violation"
        )


def test_apply_action_throttle(security_config: SecurityConfig) -> None:
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=5, action="throttle")

    with patch.object(tracker.logger, "warning") as mock_logger:
        tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")
        mock_logger.assert_called_once_with("Throttling IP 192.168.1.1: Test violation")


def test_apply_action_alert(security_config: SecurityConfig) -> None:
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=5, action="alert")

    with patch.object(tracker.logger, "critical") as mock_logger:
        tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")
        mock_logger.assert_called_once_with(
            "ALERT - Behavioral anomaly: Test violation"
        )


def test_apply_action_log_respects_log_suspicious_level(
    security_config: SecurityConfig,
) -> None:
    security_config.log_suspicious_level = "ERROR"
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=5, action="log")

    with patch.object(tracker.logger, "error") as mock_logger:
        tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")
        mock_logger.assert_called_once_with(
            "Behavioral anomaly detected: Test violation"
        )


def test_apply_action_ban_respects_log_suspicious_level(
    security_config: SecurityConfig,
) -> None:
    security_config.log_suspicious_level = "ERROR"
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=5, action="ban")

    with (
        patch(
            "guard_core.sync.handlers.ipban_handler.ip_ban_manager"
        ) as mock_ban_manager,
        patch.object(tracker.logger, "error") as mock_logger,
    ):
        mock_ban_manager._ban_ip_escalating = MagicMock()

        tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")

        mock_logger.assert_called_once()


def test_apply_action_ban_silenced_when_log_suspicious_level_none(
    security_config: SecurityConfig,
) -> None:
    security_config.log_suspicious_level = None
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=5, action="ban")

    with (
        patch(
            "guard_core.sync.handlers.ipban_handler.ip_ban_manager"
        ) as mock_ban_manager,
        patch.object(tracker.logger, "warning") as mock_warning,
    ):
        mock_ban_manager._ban_ip_escalating = MagicMock()

        tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")

        mock_ban_manager._ban_ip_escalating.assert_called_once_with(
            "192.168.1.1", 3600, "behavioral_violation", grouped=False
        )
        mock_warning.assert_not_called()


def test_apply_action_survives_a_raising_custom_action(
    security_config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> None:
    tracker = BehaviorTracker(security_config)
    custom_action = MagicMock(side_effect=RuntimeError("boom"))
    rule = BehaviorRule(rule_type="usage", threshold=5, custom_action=custom_action)

    with caplog.at_level(logging.ERROR, logger="guard_core.sync.handlers.behavior"):
        tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")

    custom_action.assert_called_once()
    assert "custom_action" in caplog.text
    assert "boom" in caplog.text


def test_execute_ban_action_returns_false_when_refused(
    security_config: SecurityConfig,
) -> None:
    tracker = BehaviorTracker(security_config)

    with patch(
        "guard_core.sync.handlers.ipban_handler.ip_ban_manager"
    ) as mock_ban_manager:
        mock_ban_manager._ban_ip_escalating = MagicMock(return_value=False)

        result = tracker._execute_ban_action("192.168.1.1", "Test violation")

        assert result == "tracked"


def test_execute_ban_action_skips_ban_when_ip_banning_disabled() -> None:
    config = SecurityConfig(enable_redis=False, enable_ip_banning=False)
    tracker = BehaviorTracker(config)

    with patch(
        "guard_core.sync.handlers.ipban_handler.ip_ban_manager"
    ) as mock_ban_manager:
        mock_ban_manager._ban_ip_escalating = MagicMock(return_value=True)

        result = tracker._execute_ban_action("192.168.1.1", "Test violation")

        assert result == "tracked"
        mock_ban_manager._ban_ip_escalating.assert_not_called()


def test_execute_ban_action_returns_true_when_applied(
    security_config: SecurityConfig,
) -> None:
    tracker = BehaviorTracker(security_config)

    with patch(
        "guard_core.sync.handlers.ipban_handler.ip_ban_manager"
    ) as mock_ban_manager:
        mock_ban_manager._ban_ip_escalating = MagicMock(return_value=True)

        result = tracker._execute_ban_action("192.168.1.1", "Test violation")

        assert result == "ban"


def test_apply_action_ban_refused_does_not_log_success(
    security_config: SecurityConfig,
) -> None:
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=5, action="ban")

    with (
        patch(
            "guard_core.sync.handlers.ipban_handler.ip_ban_manager"
        ) as mock_ban_manager,
        patch.object(tracker.logger, "warning") as mock_logger,
    ):
        mock_ban_manager._ban_ip_escalating = MagicMock(return_value=False)

        tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")

        mock_ban_manager._ban_ip_escalating.assert_called_once_with(
            "192.168.1.1", 3600, "behavioral_violation", grouped=False
        )
        mock_logger.assert_not_called()


def test_apply_action_ban_refused_reports_tracked_in_event(
    security_config: SecurityConfig,
) -> None:
    tracker = BehaviorTracker(security_config)
    tracker.agent_handler = MagicMock()
    rule = BehaviorRule(rule_type="usage", threshold=5, action="ban")

    with patch(
        "guard_core.sync.handlers.ipban_handler.ip_ban_manager"
    ) as mock_ban_manager:
        mock_ban_manager._ban_ip_escalating = MagicMock(return_value=False)

        tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")

    tracker.agent_handler.send_event.assert_called_once()
    sent_event = tracker.agent_handler.send_event.call_args[0][0]
    assert sent_event.action_taken == "tracked"


def test_apply_action_ban_applied_reports_ban_in_event(
    security_config: SecurityConfig,
) -> None:
    tracker = BehaviorTracker(security_config)
    tracker.agent_handler = MagicMock()
    rule = BehaviorRule(rule_type="usage", threshold=5, action="ban")

    with patch(
        "guard_core.sync.handlers.ipban_handler.ip_ban_manager"
    ) as mock_ban_manager:
        mock_ban_manager._ban_ip_escalating = MagicMock(return_value=True)

        tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")

    tracker.agent_handler.send_event.assert_called_once()
    sent_event = tracker.agent_handler.send_event.call_args[0][0]
    assert sent_event.action_taken == "ban"


def test_apply_action_log_silenced_when_log_suspicious_level_none(
    security_config: SecurityConfig,
) -> None:
    security_config.log_suspicious_level = None
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=5, action="log")

    with (
        patch.object(tracker.logger, "warning") as mock_warning,
        patch.object(tracker.logger, "error") as mock_error,
    ):
        tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")
        mock_warning.assert_not_called()
        mock_error.assert_not_called()


def test_apply_action_alert_ignores_log_suspicious_level(
    security_config: SecurityConfig,
) -> None:
    security_config.log_suspicious_level = None
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=5, action="alert")

    with patch.object(tracker.logger, "critical") as mock_logger:
        tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")
        mock_logger.assert_called_once_with(
            "ALERT - Behavioral anomaly: Test violation"
        )


def test_passive_mode_log_respects_log_suspicious_level(
    security_config: SecurityConfig,
) -> None:
    security_config.passive_mode = True
    security_config.log_suspicious_level = "ERROR"
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=5, action="throttle")

    with patch.object(tracker.logger, "error") as mock_logger:
        tracker._log_passive_mode_action(rule, "192.168.1.1", "Test details")
        mock_logger.assert_called_once_with(
            "[PASSIVE MODE] Would throttle IP 192.168.1.1: Test details"
        )


def test_passive_mode_log_silenced_when_log_suspicious_level_none(
    security_config: SecurityConfig,
) -> None:
    security_config.passive_mode = True
    security_config.log_suspicious_level = None
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=5, action="throttle")

    with (
        patch.object(tracker.logger, "warning") as mock_warning,
        patch.object(tracker.logger, "error") as mock_error,
    ):
        tracker._log_passive_mode_action(rule, "192.168.1.1", "Test details")
        mock_warning.assert_not_called()
        mock_error.assert_not_called()


def test_track_endpoint_usage_redis_window_boundary(
    security_config_redis: SecurityConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracker = BehaviorTracker(security_config_redis)
    redis_mgr = redis_handler(security_config_redis)
    redis_mgr.initialize()
    tracker.initialize_redis(redis_mgr)

    rule = BehaviorRule(rule_type="usage", threshold=2, window=60)
    endpoint_id = "/api/test-window-boundary"
    client_ip = "192.168.1.50"
    base_time = 2_100_000_000.0

    within_window = iter([base_time, base_time + 0.01, base_time + 0.02])
    monkeypatch.setattr(
        "guard_core.sync.handlers.behavior_handler.time.time",
        lambda: next(within_window),
    )
    assert not tracker.track_endpoint_usage(endpoint_id, client_ip, rule)
    assert not tracker.track_endpoint_usage(endpoint_id, client_ip, rule)
    assert tracker.track_endpoint_usage(endpoint_id, client_ip, rule)

    after_window = iter([base_time + 61, base_time + 62])
    monkeypatch.setattr(
        "guard_core.sync.handlers.behavior_handler.time.time",
        lambda: next(after_window),
    )
    assert not tracker.track_endpoint_usage(endpoint_id, client_ip, rule)

    redis_mgr.close()


def test_track_endpoint_usage_redis_frozen_clock_still_trips(
    security_config_redis: SecurityConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracker = BehaviorTracker(security_config_redis)
    redis_mgr = redis_handler(security_config_redis)
    redis_mgr.initialize()
    tracker.initialize_redis(redis_mgr)

    rule = BehaviorRule(rule_type="usage", threshold=10, window=60)
    endpoint_id = "/api/test-frozen-clock"
    client_ip = "192.168.1.51"
    frozen_time = 2_150_000_000.0

    monkeypatch.setattr(
        "guard_core.sync.handlers.behavior_handler.time.time", lambda: frozen_time
    )

    tripped = False
    for _ in range(50):
        tripped = tracker.track_endpoint_usage(endpoint_id, client_ip, rule)

    assert tripped

    redis_mgr.close()


def test_track_return_pattern_no_match(security_config: SecurityConfig) -> None:
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="return_pattern", threshold=1, pattern="status:404")

    response = MockGuardResponse("success", status_code=200)
    result = tracker.track_return_pattern("/api/test", "192.168.1.1", response, rule)
    assert not result


def test_track_return_pattern_window_cleanup(
    security_config: SecurityConfig,
) -> None:
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(
        rule_type="return_pattern", threshold=2, window=1, pattern="status:200"
    )

    endpoint_id = "/api/test"
    client_ip = "192.168.1.1"
    pattern_key = _rule_bucket(rule, endpoint_id)

    current_time = time.time()
    old_time = current_time - 2
    tracker.return_patterns[pattern_key][client_ip].extend([old_time, old_time])

    response = MockGuardResponse("success", status_code=200)

    result = tracker.track_return_pattern(endpoint_id, client_ip, response, rule)
    assert not result

    assert len(tracker.return_patterns[pattern_key][client_ip]) == 1


def test_track_return_pattern_evicts_the_oldest_client_a_touched_client_survives(
    security_config: SecurityConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(behavior_handler, "_MAX_TRACKED_CLIENTS_PER_ENDPOINT", 3)
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(
        rule_type="return_pattern", threshold=999, window=60, pattern="status:200"
    )
    endpoint_id = "/api/test"
    pattern_key = _rule_bucket(rule, endpoint_id)
    response = MockGuardResponse("success", status_code=200)

    for client_ip in ("203.0.113.11", "203.0.113.12", "203.0.113.13"):
        tracker.track_return_pattern(endpoint_id, client_ip, response, rule)

    tracker.track_return_pattern(endpoint_id, "203.0.113.11", response, rule)
    tracker.track_return_pattern(endpoint_id, "203.0.113.14", response, rule)

    bucket = tracker.return_patterns[pattern_key]
    assert len(bucket) == 3
    assert "203.0.113.12" not in bucket
    assert "203.0.113.11" in bucket
    assert "203.0.113.14" in bucket


def test_track_return_pattern_evicts_oldest_endpoint_touched_one_survives(
    security_config: SecurityConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(behavior_handler, "_MAX_TRACKED_ENDPOINTS", 3)
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(
        rule_type="return_pattern", threshold=999, window=60, pattern="status:200"
    )
    client_ip = "203.0.113.11"
    response = MockGuardResponse("success", status_code=200)

    for endpoint_id in ("/api/one", "/api/two", "/api/three"):
        tracker.track_return_pattern(endpoint_id, client_ip, response, rule)

    tracker.track_return_pattern("/api/one", client_ip, response, rule)
    tracker.track_return_pattern("/api/four", client_ip, response, rule)

    assert len(tracker.return_patterns) == 3
    assert _rule_bucket(rule, "/api/two") not in tracker.return_patterns
    assert _rule_bucket(rule, "/api/one") in tracker.return_patterns
    assert _rule_bucket(rule, "/api/four") in tracker.return_patterns


def test_track_return_pattern_many_endpoints_settle_at_default_bound(
    security_config: SecurityConfig,
) -> None:
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(
        rule_type="return_pattern", threshold=999, window=60, pattern="status:200"
    )
    client_ip = "203.0.113.11"
    response = MockGuardResponse("success", status_code=200)

    for i in range(15_000):
        tracker.track_return_pattern(f"/api/endpoint-{i}", client_ip, response, rule)

    assert len(tracker.return_patterns) == 10_000
    assert _rule_bucket(rule, "/api/endpoint-0") not in tracker.return_patterns
    assert _rule_bucket(rule, "/api/endpoint-14999") in tracker.return_patterns


def test_track_return_pattern_redis_window_boundary(
    security_config_redis: SecurityConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracker = BehaviorTracker(security_config_redis)
    redis_mgr = redis_handler(security_config_redis)
    redis_mgr.initialize()
    tracker.initialize_redis(redis_mgr)

    rule = BehaviorRule(
        rule_type="return_pattern", threshold=2, window=60, pattern="status:200"
    )
    endpoint_id = "/api/test-return-window-boundary"
    client_ip = "192.168.1.60"
    response = MockGuardResponse("success", status_code=200)
    base_time = 2_200_000_000.0

    within_window = iter([base_time, base_time + 0.01, base_time + 0.02])
    monkeypatch.setattr(
        "guard_core.sync.handlers.behavior_handler.time.time",
        lambda: next(within_window),
    )
    assert not tracker.track_return_pattern(endpoint_id, client_ip, response, rule)
    assert not tracker.track_return_pattern(endpoint_id, client_ip, response, rule)
    assert tracker.track_return_pattern(endpoint_id, client_ip, response, rule)

    after_window = iter([base_time + 61, base_time + 62])
    monkeypatch.setattr(
        "guard_core.sync.handlers.behavior_handler.time.time",
        lambda: next(after_window),
    )
    assert not tracker.track_return_pattern(endpoint_id, client_ip, response, rule)

    redis_mgr.close()

    redis_mgr.close()


def test_log_passive_mode_action_unknown_action_is_noop(
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    from guard_core.models import SecurityConfig
    from guard_core.sync.handlers.behavior_handler import BehaviorRule, BehaviorTracker

    tracker = BehaviorTracker(SecurityConfig())
    rule = BehaviorRule(rule_type="usage", threshold=1, action="log")
    cast(Any, rule).action = "unknown"
    with caplog.at_level(logging.INFO):
        tracker._log_passive_mode_action(rule, "1.2.3.4", "details")
    unknown_logs = [r for r in caplog.records if "details" in r.getMessage()]
    assert not unknown_logs


def test_execute_active_mode_action_unknown_action_is_noop(
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    from guard_core.models import SecurityConfig
    from guard_core.sync.handlers.behavior_handler import BehaviorRule, BehaviorTracker

    tracker = BehaviorTracker(SecurityConfig())
    rule = BehaviorRule(rule_type="usage", threshold=1, action="log")
    cast(Any, rule).action = "unknown"
    with caplog.at_level(logging.INFO):
        tracker._execute_active_mode_action(rule, "1.2.3.4", "ep", "details")
    unknown_logs = [r for r in caplog.records if "details" in r.getMessage()]
    assert not unknown_logs


def test_track_endpoint_usage_redis_glob_client_ip_does_not_leak_other_clients(
    security_config_redis: SecurityConfig,
) -> None:
    tracker = BehaviorTracker(security_config_redis)
    redis_mgr = redis_handler(security_config_redis)
    redis_mgr.initialize()
    tracker.initialize_redis(redis_mgr)

    rule = BehaviorRule(rule_type="usage", threshold=3, window=60)
    endpoint_id = "/api/injection-client-ip"
    victim_ip = "10.9.9.9"

    for _ in range(5):
        tracker.track_endpoint_usage(endpoint_id, victim_ip, rule)

    attacker_client_ip = "*"
    tripped = tracker.track_endpoint_usage(endpoint_id, attacker_client_ip, rule)
    assert not tripped

    redis_mgr.close()


def test_track_endpoint_usage_redis_glob_endpoint_id_does_not_leak(
    security_config_redis: SecurityConfig,
) -> None:
    tracker = BehaviorTracker(security_config_redis)
    redis_mgr = redis_handler(security_config_redis)
    redis_mgr.initialize()
    tracker.initialize_redis(redis_mgr)

    rule = BehaviorRule(rule_type="usage", threshold=3, window=60)
    victim_client_ip = "10.9.9.10"
    victim_endpoint_id = "/api/injection-endpoint-victim"

    for _ in range(5):
        tracker.track_endpoint_usage(victim_endpoint_id, victim_client_ip, rule)

    attacker_endpoint_id = "*"
    tripped = tracker.track_endpoint_usage(attacker_endpoint_id, victim_client_ip, rule)
    assert not tripped

    redis_mgr.close()


def test_track_return_pattern_redis_glob_pattern_does_not_leak_other_patterns(
    security_config_redis: SecurityConfig,
) -> None:
    security_config_redis.behavior_scan_response_body = True
    tracker = BehaviorTracker(security_config_redis)
    redis_mgr = redis_handler(security_config_redis)
    redis_mgr.initialize()
    tracker.initialize_redis(redis_mgr)

    endpoint_id = "/api/injection-pattern"
    client_ip = "10.9.9.11"
    response = _BoundedReaderResponse(b"matched*", status_code=200)

    rule_a = BehaviorRule(
        rule_type="return_pattern", threshold=3, window=60, pattern="matched"
    )
    for _ in range(5):
        tracker.track_return_pattern(endpoint_id, client_ip, response, rule_a)

    rule_b = BehaviorRule(
        rule_type="return_pattern", threshold=3, window=60, pattern="*"
    )
    tripped = tracker.track_return_pattern(endpoint_id, client_ip, response, rule_b)
    assert not tripped

    redis_mgr.close()


def test_track_endpoint_usage_redis_isolates_all_glob_metacharacters(
    security_config_redis: SecurityConfig,
) -> None:
    tracker = BehaviorTracker(security_config_redis)
    redis_mgr = redis_handler(security_config_redis)
    redis_mgr.initialize()
    tracker.initialize_redis(redis_mgr)

    rule = BehaviorRule(rule_type="usage", threshold=3, window=60)
    endpoint_id = "/api/injection-metachar-sweep"
    victim_ip = "10.9.9.12"

    for _ in range(5):
        tracker.track_endpoint_usage(endpoint_id, victim_ip, rule)

    for metachar in ("*", "?", "[", "]", "\\", "[abc]", "a*b", "a?b"):
        tripped = tracker.track_endpoint_usage(endpoint_id, metachar, rule)
        assert not tripped, f"metachar {metachar!r} leaked victim's usage history"

    redis_mgr.close()


def test_track_endpoint_usage_redis_ordinary_identities_still_isolated(
    security_config_redis: SecurityConfig,
) -> None:
    tracker = BehaviorTracker(security_config_redis)
    redis_mgr = redis_handler(security_config_redis)
    redis_mgr.initialize()
    tracker.initialize_redis(redis_mgr)

    rule = BehaviorRule(rule_type="usage", threshold=1, window=60)
    endpoint_id = "/api/injection-ordinary-sweep"

    for client_ip in ("10.9.9.20", "10.9.9.21", "2001:db8::1"):
        assert not tracker.track_endpoint_usage(endpoint_id, client_ip, rule)
        assert tracker.track_endpoint_usage(endpoint_id, client_ip, rule)

    redis_mgr.close()


def test_track_endpoint_usage_redis_hashing_prevents_field_boundary_collision(
    security_config_redis: SecurityConfig,
) -> None:
    tracker = BehaviorTracker(security_config_redis)
    redis_mgr = redis_handler(security_config_redis)
    redis_mgr.initialize()
    tracker.initialize_redis(redis_mgr)

    rule = BehaviorRule(rule_type="usage", threshold=3, window=60)

    for _ in range(5):
        tracker.track_endpoint_usage("a:b", "c", rule)

    tripped = tracker.track_endpoint_usage("a", "b:c", rule)
    assert not tripped

    redis_mgr.close()


def test_track_return_pattern_redis_hashing_prevents_field_boundary_collision(
    security_config_redis: SecurityConfig,
) -> None:
    security_config_redis.behavior_scan_response_body = True
    tracker = BehaviorTracker(security_config_redis)
    redis_mgr = redis_handler(security_config_redis)
    redis_mgr.initialize()
    tracker.initialize_redis(redis_mgr)

    response = _BoundedReaderResponse(b"matched", status_code=200)
    rule = BehaviorRule(
        rule_type="return_pattern", threshold=3, window=60, pattern="matched"
    )

    for _ in range(5):
        tracker.track_return_pattern("a:b", "c", response, rule)

    tripped = tracker.track_return_pattern("a", "b:c", response, rule)
    assert not tripped

    redis_mgr.close()
