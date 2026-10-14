import asyncio
import concurrent.futures
import re
import time
from collections.abc import Iterator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core._utils.detection_scan import _fallback_pattern_check
from guard_core.decorators.content_filtering import ContentFilteringMixin
from guard_core.detection_engine._redos_cost_arbiter import (
    _log_structural_disagreement,
)
from guard_core.detection_engine.monitor import PerformanceMonitor
from guard_core.detection_engine.monitor_anomalies import (
    build_anomaly_event_data,
    sanitize_anomaly_data,
)
from guard_core.detection_engine.monitor_reporting import build_pattern_report
from guard_core.detection_engine.monitor_types import PatternStats
from guard_core.handlers import suspatterns_handler as sph
from guard_core.handlers._behavior_response_pattern import (
    BehaviorResponsePatternMixin,
)
from guard_core.handlers._dynamic_rule_application import DynamicRuleApplicationMixin
from guard_core.handlers.suspatterns_handler import SusPatternsManager
from guard_core.models import DynamicRules, SecurityConfig

_SECRET_PATTERN = r"password=hunter2SuperSecretValue"


@pytest.fixture
def fresh_legacy_singleton() -> Iterator[SusPatternsManager]:
    saved_instance = SusPatternsManager._instance
    saved_config = SusPatternsManager._config
    saved_global = sph.sus_patterns_handler

    SusPatternsManager._instance = None
    SusPatternsManager._config = None
    legacy = SusPatternsManager()
    sph.sus_patterns_handler = legacy

    yield legacy

    SusPatternsManager._instance = saved_instance
    SusPatternsManager._config = saved_config
    sph.sus_patterns_handler = saved_global


async def test_check_regex_pattern_timeout_log_redacts_secret_shaped_custom_pattern(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    manager = fresh_legacy_singleton
    manager.configure(SecurityConfig(detection_compiler_timeout=0.1))
    ok = await manager.add_pattern(_SECRET_PATTERN, custom=True)
    assert ok

    compiled = re.compile(_SECRET_PATTERN, re.IGNORECASE | re.MULTILINE)
    fake_pattern_start = time.monotonic() - 1000.0

    with patch("guard_core.handlers._suspatterns_regex.logger") as mock_logger:
        threat, timed_out = await manager._check_regex_pattern(
            compiled, "unrelated content", "203.0.113.5", fake_pattern_start, "custom"
        )

    assert threat is None
    assert timed_out is True
    logged = " ".join(str(call) for call in mock_logger.warning.call_args_list)
    assert "hunter2" not in logged
    assert "[REDACTED]" in logged


async def test_check_regex_pattern_timeout_log_leaves_builtin_pattern_unchanged(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    manager = fresh_legacy_singleton
    manager.configure(SecurityConfig(detection_compiler_timeout=0.1))
    builtin_source = r"[a-z]+attackterm[a-z]+"
    compiled = re.compile(builtin_source)
    fake_pattern_start = time.monotonic() - 1000.0

    with patch("guard_core.handlers._suspatterns_regex.logger") as mock_logger:
        await manager._check_regex_pattern(
            compiled, "unrelated content", "203.0.113.5", fake_pattern_start, "custom"
        )

    logged = " ".join(str(call) for call in mock_logger.warning.call_args_list)
    assert builtin_source[:50] in logged
    assert "[REDACTED]" not in logged


async def test_check_windowed_pattern_timeout_log_redacts_secret_shaped_pattern(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    manager = fresh_legacy_singleton

    def _finder(_content: str) -> Iterator[re.Match[str]]:
        yield from ()

    pattern = re.compile(_SECRET_PATTERN)
    with patch(
        "guard_core.handlers._suspatterns_regex.shared_regex_executor"
    ) as mock_executor:
        mock_future: concurrent.futures.Future[None] = concurrent.futures.Future()
        mock_future.set_exception(concurrent.futures.TimeoutError())
        mock_executor.return_value.submit.return_value = mock_future

        with patch("guard_core.handlers._suspatterns_regex.logger") as mock_logger:
            threat, timed_out = await manager._check_windowed_pattern(
                pattern, _finder, "content", time.monotonic(), "custom", "unknown"
            )

    assert threat is None
    assert timed_out is True
    logged = " ".join(str(call) for call in mock_logger.warning.call_args_list)
    assert "hunter2" not in logged
    assert "[REDACTED]" in logged


async def test_check_windowed_pattern_exception_log_redacts_secret_shaped_pattern(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    manager = fresh_legacy_singleton

    def _finder(_content: str) -> Iterator[re.Match[str]]:
        yield from ()

    pattern = re.compile(_SECRET_PATTERN)
    with patch(
        "guard_core.handlers._suspatterns_regex.shared_regex_executor"
    ) as mock_executor:
        mock_future: concurrent.futures.Future[None] = concurrent.futures.Future()
        mock_future.set_exception(RuntimeError("boom"))
        mock_executor.return_value.submit.return_value = mock_future

        with patch("guard_core.handlers._suspatterns_regex.logger") as mock_logger:
            threat, timed_out = await manager._check_windowed_pattern(
                pattern, _finder, "content", time.monotonic(), "custom", "unknown"
            )

    assert threat is None
    assert timed_out is False
    logged = " ".join(str(call) for call in mock_logger.error.call_args_list)
    assert "hunter2" not in logged
    assert "[REDACTED]" in logged


async def test_check_pattern_with_timeout_log_redacts_secret_shaped_pattern(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    manager = fresh_legacy_singleton
    manager._config = MagicMock(detection_compiler_timeout=0.1)
    pattern = re.compile(_SECRET_PATTERN)

    with patch(
        "guard_core.handlers._suspatterns_regex.shared_regex_executor"
    ) as mock_executor:
        mock_future: concurrent.futures.Future[None] = concurrent.futures.Future()
        mock_future.set_exception(concurrent.futures.TimeoutError())
        mock_executor.return_value.submit.return_value = mock_future

        with patch("guard_core.handlers._suspatterns_regex.logger") as mock_logger:
            match, timed_out = await manager._check_pattern_with_timeout(
                pattern, "content", "203.0.113.5", 0.0
            )

    assert match is None
    assert timed_out is True
    logged = " ".join(str(call) for call in mock_logger.warning.call_args_list)
    assert "hunter2" not in logged
    assert "[REDACTED]" in logged


async def test_check_pattern_with_timeout_exception_log_redacts_secret_shaped_pattern(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    manager = fresh_legacy_singleton
    manager._config = MagicMock(detection_compiler_timeout=0.1)
    pattern = re.compile(_SECRET_PATTERN)

    with patch(
        "guard_core.handlers._suspatterns_regex.shared_regex_executor"
    ) as mock_executor:
        mock_future: concurrent.futures.Future[None] = concurrent.futures.Future()
        mock_future.set_exception(RuntimeError("boom"))
        mock_executor.return_value.submit.return_value = mock_future

        with patch("guard_core.handlers._suspatterns_regex.logger") as mock_logger:
            match, timed_out = await manager._check_pattern_with_timeout(
                pattern, "content", "203.0.113.5", 0.0
            )

    assert match is None
    assert timed_out is False
    logged = " ".join(str(call) for call in mock_logger.error.call_args_list)
    assert "hunter2" not in logged
    assert "[REDACTED]" in logged


async def test_detect_pattern_match_returns_redacted_pattern_label(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    manager = fresh_legacy_singleton
    manager._config = SecurityConfig()
    ok = await manager.add_pattern(_SECRET_PATTERN, custom=True)
    assert ok

    is_threat, pattern_label = await manager.detect_pattern_match(
        _SECRET_PATTERN, "203.0.113.9", context="request_body"
    )

    assert is_threat is True
    assert pattern_label is not None
    assert "hunter2" not in pattern_label
    assert "[REDACTED]" in pattern_label


async def test_add_pattern_rejects_unsafe_pattern_without_leaking_secret_in_log(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    manager = fresh_legacy_singleton
    unsafe_pattern = "(unterminated[" + _SECRET_PATTERN

    with patch("guard_core.handlers._suspatterns_registry.logger") as mock_logger:
        ok = await manager.add_pattern(unsafe_pattern, custom=True)

    assert ok is False
    logged = " ".join(str(call) for call in mock_logger.warning.call_args_list)
    assert "hunter2" not in logged
    assert "[REDACTED]" in logged


async def test_dynamic_rule_apply_pattern_rules_logs_redact_secret_shaped_pattern(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    class _Applier(DynamicRuleApplicationMixin):
        def __init__(self) -> None:
            import logging

            self.config = SecurityConfig()
            self.agent_handler = None
            self.logger = logging.getLogger(
                "guard_core.handlers.dynamic_rule_test_pattern_redaction"
            )

    applier = _Applier()
    rules = DynamicRules(
        rule_id="r1",
        version=1,
        timestamp="2026-09-04T00:00:00Z",
        suspicious_patterns=[_SECRET_PATTERN, "(unterminated["],
    )

    with patch.object(applier, "logger") as mock_logger:
        await applier._apply_pattern_rules(rules.suspicious_patterns)

    logged = " ".join(
        str(call)
        for call in (
            mock_logger.info.call_args_list + mock_logger.warning.call_args_list
        )
    )
    assert "hunter2" not in logged
    assert "[REDACTED]" in logged


async def test_anomaly_event_to_agent_redacts_secret_shaped_pattern() -> None:
    monitor = PerformanceMonitor()
    agent = MagicMock()
    agent.send_event = AsyncMock()

    await monitor.record_metric(
        pattern=_SECRET_PATTERN,
        execution_time=2.5,
        content_length=100,
        matched=False,
        timeout=True,
        agent_handler=agent,
        correlation_id="corr-1",
    )

    assert agent.send_event.await_count >= 1
    for call in agent.send_event.await_args_list:
        event = call.args[0]
        metadata = getattr(event, "metadata", {})
        assert "hunter2" not in str(metadata.get("pattern", ""))
        assert "[REDACTED]" in str(metadata.get("pattern", ""))


def test_build_anomaly_event_data_redacts_secret_shaped_pattern() -> None:
    anomaly = {"type": "timeout", "pattern": _SECRET_PATTERN, "content_length": 10}
    event_data = build_anomaly_event_data(anomaly, "corr-1")
    assert "hunter2" not in str(event_data["metadata"]["pattern"])
    assert event_data["metadata"]["pattern"] == "[REDACTED]"


def test_build_anomaly_event_data_without_pattern_key() -> None:
    anomaly = {"type": "timeout"}
    event_data = build_anomaly_event_data(anomaly, "corr-1")
    assert "pattern" not in event_data["metadata"]


def test_sanitize_anomaly_data_redacts_secret_shaped_pattern() -> None:
    anomaly = {"type": "timeout", "pattern": _SECRET_PATTERN}
    safe = sanitize_anomaly_data(anomaly)
    assert "hunter2" not in safe["pattern"]
    assert safe["pattern"] == "[REDACTED]"


def test_build_pattern_report_redacts_secret_shaped_pattern() -> None:
    stats = PatternStats(
        pattern=_SECRET_PATTERN,
        total_executions=10,
        total_matches=5,
        total_timeouts=1,
        avg_execution_time=0.05,
        max_execution_time=0.1,
        min_execution_time=0.01,
    )
    report = build_pattern_report(_SECRET_PATTERN, stats)
    assert "hunter2" not in report["pattern"]
    assert "[REDACTED]" in report["pattern"]


def test_build_pattern_report_leaves_builtin_pattern_unchanged() -> None:
    builtin_source = "test_pattern"
    stats = PatternStats(
        pattern=builtin_source,
        total_executions=10,
        total_matches=5,
        total_timeouts=1,
        avg_execution_time=0.05,
        max_execution_time=0.1,
        min_execution_time=0.01,
    )
    report = build_pattern_report(builtin_source, stats)
    assert report["pattern"] == builtin_source


async def test_dynamic_rule_apply_user_agent_rules_logs_redact_secret_shaped_pattern(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    class _Applier(DynamicRuleApplicationMixin):
        def __init__(self) -> None:
            import logging

            self.config = SecurityConfig()
            self.agent_handler = None
            self.logger = logging.getLogger(
                "guard_core.handlers.dynamic_rule_test_user_agent_redaction"
            )

    applier = _Applier()
    with patch.object(applier, "logger") as mock_logger:
        await applier._apply_user_agent_rules(
            [_SECRET_PATTERN, "(a+)+" + _SECRET_PATTERN + "$"]
        )

    assert mock_logger.warning.called
    logged = " ".join(
        str(call)
        for call in (
            mock_logger.info.call_args_list + mock_logger.warning.call_args_list
        )
    )
    assert "hunter2" not in logged
    assert "[REDACTED]" in logged


async def test_fallback_pattern_check_recursion_log_redacts_secret_shaped_pattern(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    manager = fresh_legacy_singleton
    manager.configure(SecurityConfig())
    ok = await manager.add_pattern(_SECRET_PATTERN, custom=True)
    assert ok

    async def raising(
        pattern: re.Pattern[str],
        value: str,
        client_ip: str,
        pattern_start: float,
        category: str,
        context: str = "unknown",
        binary_prefix: list[int] | None = None,
    ) -> tuple[None, bool]:
        raise RecursionError("simulated regex recursion")

    with (
        patch.object(manager, "_check_regex_pattern", raising),
        patch("guard_core._utils.detection_scan.logger") as mock_logger,
    ):
        detected, _ = await _fallback_pattern_check(
            "probe value", "203.0.113.9", "request_body"
        )

    assert detected is False
    logged = " ".join(str(call) for call in mock_logger.warning.call_args_list)
    assert "hunter2" not in logged
    assert "[REDACTED]" in logged


def test_structural_disagreement_log_redacts_secret_shaped_pattern(
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    with patch("guard_core.detection_engine._redos_cost_arbiter.logger") as mock_logger:
        _log_structural_disagreement(_SECRET_PATTERN, "nested quantifier", 64, "timing")

    logged = " ".join(str(call) for call in mock_logger.warning.call_args_list)
    assert "hunter2" not in logged
    assert "[REDACTED]" in logged


_CATASTROPHIC_SECRET_PATTERN = "(a+)+" + _SECRET_PATTERN + "$"


def test_security_config_blocked_user_agents_rejection_redacts_secret_pattern() -> None:
    with pytest.raises(ValueError) as excinfo:
        SecurityConfig(blocked_user_agents=[_CATASTROPHIC_SECRET_PATTERN])
    assert "hunter2" not in str(excinfo.value)
    assert "[REDACTED]" in str(excinfo.value)


def test_security_config_return_pattern_without_body_scan_redacts_secret_pattern() -> (
    None
):
    with pytest.raises(ValueError) as excinfo:
        SecurityConfig(
            global_behavior_rules=[
                {
                    "rule_type": "return_pattern",
                    "threshold": 1,
                    "window": 60,
                    "pattern": _SECRET_PATTERN,
                    "action": "log",
                }
            ],
            behavior_scan_response_body=False,
        )
    assert "hunter2" not in str(excinfo.value)
    assert "[REDACTED]" in str(excinfo.value)


def test_block_user_agents_decorator_rejection_redacts_secret_pattern() -> None:
    class _Decorator(ContentFilteringMixin):
        def __init__(self) -> None:
            self.config = SecurityConfig()

    with pytest.raises(ValueError) as excinfo:
        _Decorator().block_user_agents([_CATASTROPHIC_SECRET_PATTERN])
    assert "hunter2" not in str(excinfo.value)
    assert "[REDACTED]" in str(excinfo.value)


def test_behavior_body_unavailable_warning_redacts_secret_pattern() -> None:
    from cachetools import TTLCache

    class _Mixin(BehaviorResponsePatternMixin):
        def __init__(self) -> None:
            import logging

            self.config = SecurityConfig()
            self.logger = logging.getLogger("guard_core.test_body_unavailable")
            self._body_unavailable_log_cache = TTLCache(maxsize=8, ttl=60)

    mixin = _Mixin()
    with patch.object(mixin, "logger") as mock_logger:
        mixin._log_body_unavailable(_SECRET_PATTERN)
    logged = " ".join(str(call) for call in mock_logger.warning.call_args_list)
    assert "hunter2" not in logged
    assert "[REDACTED]" in logged


@pytest.mark.parametrize(
    "source",
    [
        r"password\s*=\s*hunter2SECRET",
        r"password[:=]hunter2SECRET",
        r"password\s+:\s*hunter2SECRET",
        r"password(?:=|:)hunter2SECRET",
        r"password\ =hunter2SECRET",
        r"password={1}hunter2SECRET",
        r"(?:password)\s*=\s*hunter2SECRET$",
        r"password[ \t]*=[ \t]*hunter2SECRET",
        r"password.{0,3}=hunter2SECRET",
    ],
)
def test_pattern_source_with_regex_syntax_between_name_and_value_is_redacted(
    source: str,
) -> None:
    from guard_core._utils.detection_scan import _redact_pattern_source

    redacted = _redact_pattern_source(source)
    assert "hunter2" not in redacted
    assert redacted == "[REDACTED]"


@pytest.mark.parametrize(
    "source",
    [
        r"password(?:\s|%20)*=hunter2",
        r"PASS\x57ORD=hunter2",
        r"pass\167ord=hunter2",
        r"pass\u0077ord=hunter2",
        r"password\x20*=hunter2",
        r"[pP]assword\s*=hunter2",
        r"password\s*(?P<eq>=)\s*hunter2",
        r"password\s*=\s*(?:hunter2|other)",
        r"password\s*=\s*(hunter2|topsecret|swordfish)",
        r"(?<=user:)password\s*=\s*hunter2",
        r"password\s*=\s*hunter2(?=;)",
        r"hunter2\s*=\s*password",
        r"password\s*=\s*hunter2(?!;)",
        r"(?i)password\s*=\s*hunter2",
    ],
)
def test_pattern_source_adversarial_regex_shapes_are_fully_redacted(
    source: str,
) -> None:
    from guard_core._utils.detection_scan import _redact_pattern_source

    redacted = _redact_pattern_source(source)
    assert "hunter2" not in redacted
    assert "topsecret" not in redacted
    assert "swordfish" not in redacted
    assert redacted == "[REDACTED]"


@pytest.mark.parametrize(
    "source", [r"<script[^>]*>", r"(?i)union\s+select", r"note\s*=\s*\w+", r"\.env"]
)
def test_pattern_source_without_a_sensitive_pair_is_displayed_unchanged(
    source: str,
) -> None:
    from guard_core._utils.detection_scan import _redact_pattern_source

    assert _redact_pattern_source(source) == source


def test_builtin_pattern_table_redaction_count() -> None:
    from guard_core._utils.detection_scan import _redact_pattern_source
    from guard_core.handlers._suspatterns_pattern_table import _PATTERN_DEFINITIONS

    redacted_categories = []
    for pattern, _contexts, category in _PATTERN_DEFINITIONS:
        redacted = _redact_pattern_source(pattern)
        if redacted == "[REDACTED]":
            redacted_categories.append(category)
        else:
            assert redacted == pattern

    assert len(_PATTERN_DEFINITIONS) == 157
    assert sorted(redacted_categories) == ["http_split", "recon"]


async def test_concurrent_configure_redacts_both_custom_names(  # async-only
    fresh_legacy_singleton: SusPatternsManager,
) -> None:
    from guard_core._utils.detection_scan import _redact_pattern_source
    from guard_core._utils.penetration_detection import (
        _ensure_detection_singleton_configured,
    )

    config_a = SecurityConfig(
        enable_penetration_detection=True, log_sensitive_headers={"x-secret-a"}
    )
    config_b = SecurityConfig(
        enable_penetration_detection=True, log_sensitive_headers={"x-secret-b"}
    )

    pattern_a = r"x-secret-a\s*=\s*hunter2aaa"
    pattern_b = r"x-secret-b\s*=\s*hunter2bbb"

    leaked = []

    async def probe_a(i: int) -> None:
        _ensure_detection_singleton_configured(config_a)
        await asyncio.sleep(0)
        redacted = _redact_pattern_source(pattern_a)
        if "hunter2aaa" in redacted:
            leaked.append(("A", i, redacted))

    async def probe_b(i: int) -> None:
        _ensure_detection_singleton_configured(config_b)
        await asyncio.sleep(0)
        redacted = _redact_pattern_source(pattern_b)
        if "hunter2bbb" in redacted:
            leaked.append(("B", i, redacted))

    tasks = []
    for i in range(200):
        tasks.append(probe_a(i))
        tasks.append(probe_b(i))
    await asyncio.gather(*tasks)

    assert leaked == []
