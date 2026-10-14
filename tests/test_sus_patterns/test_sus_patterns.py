import concurrent.futures
import logging
import re
import time
from collections.abc import Callable
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.handlers import suspatterns_handler as _suspatterns_module
from guard_core.handlers.redis_handler import RedisManager
from guard_core.handlers.suspatterns_handler import (
    _LEGACY_DETECTION_WARNING,
    SusPatternsManager,
    sus_patterns_handler,
)
from guard_core.models import SecurityConfig


@pytest.mark.asyncio
async def test_add_pattern() -> None:
    pattern_to_add = r"new_pattern"
    await sus_patterns_handler.add_pattern(pattern_to_add, custom=True)
    assert pattern_to_add in sus_patterns_handler.custom_patterns


@pytest.mark.asyncio
async def test_remove_pattern() -> None:
    pattern_to_remove = r"new_pattern"
    await sus_patterns_handler.add_pattern(pattern_to_remove, custom=True)
    result = await sus_patterns_handler.remove_pattern(pattern_to_remove, custom=True)
    assert result is True
    assert pattern_to_remove not in sus_patterns_handler.custom_patterns


@pytest.mark.asyncio
async def test_get_all_patterns() -> None:
    default_patterns = sus_patterns_handler.patterns
    custom_pattern = r"custom_pattern"
    await sus_patterns_handler.add_pattern(custom_pattern, custom=True)
    all_patterns = await sus_patterns_handler.get_all_patterns()
    assert custom_pattern in all_patterns
    assert all(pattern in all_patterns for pattern in default_patterns)


@pytest.mark.asyncio
async def test_get_default_patterns() -> None:
    default_patterns = sus_patterns_handler.patterns
    custom_pattern = r"custom_pattern_test"
    await sus_patterns_handler.add_pattern(custom_pattern, custom=True)

    patterns = await sus_patterns_handler.get_default_patterns()

    assert custom_pattern not in patterns
    assert all(pattern in patterns for pattern in default_patterns)


@pytest.mark.asyncio
async def test_get_custom_patterns() -> None:
    custom_pattern = r"custom_pattern_only"
    await sus_patterns_handler.add_pattern(custom_pattern, custom=True)

    patterns = await sus_patterns_handler.get_custom_patterns()

    assert custom_pattern in patterns
    default_pattern = sus_patterns_handler.patterns[0]
    assert default_pattern not in patterns


@pytest.mark.asyncio
async def test_invalid_pattern_rejected_without_raising() -> None:
    pattern = r"invalid(regex"

    ok = await sus_patterns_handler.add_pattern(pattern, custom=True)

    assert ok is False
    assert pattern not in sus_patterns_handler.custom_patterns


@pytest.mark.asyncio
async def test_remove_nonexistent_pattern() -> None:
    result = await sus_patterns_handler.remove_pattern("nonexistent", custom=True)
    assert result is False


def test_singleton_behavior() -> None:
    instance1 = sus_patterns_handler
    instance2 = sus_patterns_handler
    assert instance1 is instance2
    assert instance1.compiled_patterns is instance2.compiled_patterns


@pytest.mark.asyncio
async def test_add_default_pattern() -> None:
    pattern_to_add = r"default_pattern"
    initial_length = len(sus_patterns_handler.patterns)

    await sus_patterns_handler.add_pattern(pattern_to_add, custom=False)

    assert len(sus_patterns_handler.patterns) == initial_length + 1
    assert pattern_to_add in sus_patterns_handler.patterns


@pytest.mark.asyncio
async def test_remove_default_pattern() -> None:
    sus_patterns_handler._instance = None
    original_patterns = sus_patterns_handler.patterns.copy()

    try:
        pattern_to_remove = r"default_pattern"

        await sus_patterns_handler.add_pattern(pattern_to_remove, custom=False)

        result = await sus_patterns_handler.remove_pattern(
            pattern_to_remove, custom=False
        )

        assert result is True
        assert pattern_to_remove not in sus_patterns_handler.patterns
        assert len(sus_patterns_handler.patterns) == len(original_patterns)

    finally:
        sus_patterns_handler.patterns = original_patterns.copy()
        sus_patterns_handler._instance = None


@pytest.mark.asyncio
async def test_get_compiled_patterns_separation() -> None:
    default_pattern = r"default_test_pattern_\d+"
    custom_pattern = r"custom_test_pattern_\d+"

    await sus_patterns_handler.add_pattern(default_pattern, custom=False)
    await sus_patterns_handler.add_pattern(custom_pattern, custom=True)

    default_compiled = await sus_patterns_handler.get_default_compiled_patterns()
    custom_compiled = await sus_patterns_handler.get_custom_compiled_patterns()

    test_default_string = "default_test_pattern_123"
    default_matched = any(
        p.search(test_default_string) for p, _ctx, _cat in default_compiled
    )
    assert default_matched

    test_custom_string = "custom_test_pattern_456"
    custom_matched = any(
        p.search(test_custom_string) for p, _ctx, _cat in custom_compiled
    )
    assert custom_matched

    assert len(default_compiled) == len(sus_patterns_handler.compiled_patterns)
    assert len(custom_compiled) == len(sus_patterns_handler.compiled_custom_patterns)


@pytest.mark.asyncio
async def test_redis_initialization(security_config_redis: SecurityConfig) -> None:
    redis_handler = RedisManager(security_config_redis)
    await redis_handler.initialize()

    test_patterns = "pattern1,pattern2,pattern3"
    await redis_handler.set_key("patterns", "custom", test_patterns)

    await sus_patterns_handler.initialize_redis(redis_handler)

    for pattern in test_patterns.split(","):
        assert pattern in sus_patterns_handler.custom_patterns

    await redis_handler.close()


@pytest.mark.asyncio
async def test_redis_pattern_persistence(security_config_redis: SecurityConfig) -> None:
    redis_handler = RedisManager(security_config_redis)
    await redis_handler.initialize()

    await sus_patterns_handler.initialize_redis(redis_handler)

    test_pattern = "test_pattern"
    await sus_patterns_handler.add_pattern(test_pattern, custom=True)

    cached_patterns = await redis_handler.get_key("patterns", "custom")
    assert test_pattern in cached_patterns.split(",")

    result = await sus_patterns_handler.remove_pattern(test_pattern, custom=True)
    assert result is True

    cached_patterns = await redis_handler.get_key("patterns", "custom")
    assert not cached_patterns or test_pattern not in cached_patterns.split(",")

    await redis_handler.close()


@pytest.mark.asyncio
async def test_redis_disabled() -> None:
    await sus_patterns_handler.initialize_redis(None)

    test_pattern = "test_pattern"
    await sus_patterns_handler.add_pattern(test_pattern, custom=True)
    assert test_pattern in sus_patterns_handler.custom_patterns

    result = await sus_patterns_handler.remove_pattern(test_pattern, custom=True)
    assert result is True
    assert test_pattern not in sus_patterns_handler.custom_patterns


@pytest.mark.asyncio
async def test_get_all_compiled_patterns() -> None:
    test_pattern = r"test_pattern\d+"
    await sus_patterns_handler.add_pattern(test_pattern, custom=True)

    compiled_patterns = await sus_patterns_handler.get_all_compiled_patterns()

    assert len(compiled_patterns) == len(sus_patterns_handler.compiled_patterns) + len(
        sus_patterns_handler.compiled_custom_patterns
    )

    test_string = "test_pattern123"
    matched = False
    for pattern, _ctx, _cat in compiled_patterns:
        if pattern.search(test_string):
            matched = True
            break
    assert matched


@pytest.mark.asyncio
async def test_init_with_full_enhanced_config() -> None:
    config = MagicMock()
    config.detection_compiler_timeout = 3.0
    config.detection_max_tracked_patterns = 500
    config.detection_max_content_length = 20000
    config.detection_preserve_attack_patterns = True
    config.detection_anomaly_threshold = 2.5
    config.detection_slow_pattern_threshold = 0.2
    config.detection_monitor_history_size = 100
    config.detection_semantic_threshold = 0.8
    config.detection_anomaly_emission_cooldown = 45.0
    config.detection_min_samples_for_anomaly = 25
    config.detection_threat_score_threshold = 1.5

    SusPatternsManager._instance = None
    manager = SusPatternsManager(config)

    assert manager._compiler is not None
    assert manager._compiler.default_timeout == 3.0
    assert manager._preprocessor is not None
    assert manager._preprocessor.max_content_length == 20000
    assert manager._preprocessor.preserve_attack_patterns is True
    assert manager._semantic_analyzer is not None
    assert manager._performance_monitor is not None
    assert manager._performance_monitor.anomaly_threshold == 2.5
    assert manager._performance_monitor.slow_pattern_threshold == 0.2
    assert manager._performance_monitor.anomaly_emission_cooldown == 45.0
    assert manager._performance_monitor.min_samples_for_anomaly == 25
    assert manager._semantic_threshold == 0.8
    assert manager._threat_score_threshold == 1.5

    SusPatternsManager._instance = None


class _PartialDetectionConfig:
    detection_compiler_timeout = 3.0
    detection_max_tracked_patterns = 500
    detection_max_content_length = 20000
    detection_preserve_attack_patterns = True
    detection_anomaly_threshold = 2.5
    detection_slow_pattern_threshold = 0.2
    detection_monitor_history_size = 100
    detection_semantic_threshold = 0.8
    detection_threat_score_threshold = 1.0


@pytest.mark.asyncio
async def test_init_with_config_missing_new_fields_falls_back_to_legacy() -> None:
    config = _PartialDetectionConfig()
    assert not hasattr(config, "detection_anomaly_emission_cooldown")
    assert not hasattr(config, "detection_min_samples_for_anomaly")

    SusPatternsManager._instance = None
    manager = SusPatternsManager(config)

    assert manager._compiler is None
    assert manager._preprocessor is None
    assert manager._semantic_analyzer is None
    assert manager._performance_monitor is None
    assert manager._semantic_threshold == 0.7
    assert manager._threat_score_threshold == 1.0

    SusPatternsManager._instance = None


@pytest.mark.asyncio
async def test_unconfigured_detection_warns_once_with_deprecation_text(
    caplog: pytest.LogCaptureFixture,
) -> None:
    SusPatternsManager._instance = None
    manager = SusPatternsManager()
    assert manager._compiler is None
    _suspatterns_module._legacy_detection_warned = False

    try:
        with caplog.at_level(logging.WARNING, logger="guard_core.handlers.suspatterns"):
            with pytest.warns(
                DeprecationWarning, match=re.escape(_LEGACY_DETECTION_WARNING)
            ):
                await manager.detect("hello", "127.0.0.1", "test_legacy_warning")
        assert _LEGACY_DETECTION_WARNING in caplog.text

        caplog.clear()
        await manager.detect("hello again", "127.0.0.1", "test_legacy_warning")
        assert _LEGACY_DETECTION_WARNING not in caplog.text
    finally:
        _suspatterns_module._legacy_detection_warned = True
        SusPatternsManager._instance = None


@pytest.mark.asyncio
async def test_configured_detection_never_warns() -> None:
    SusPatternsManager._instance = None
    manager = SusPatternsManager(SecurityConfig())
    assert manager._compiler is not None
    _suspatterns_module._legacy_detection_warned = False

    try:
        await manager.detect("hello", "127.0.0.1", "test_no_legacy_warning")
    finally:
        _suspatterns_module._legacy_detection_warned = True
        SusPatternsManager._instance = None


@pytest.mark.asyncio
async def test_regex_timeout_fallback() -> None:
    SusPatternsManager._instance = None
    manager = SusPatternsManager()

    original_compiler = manager._compiler
    manager._compiler = None

    evil_pattern = r"a{100,}b"
    await manager.add_pattern(evil_pattern, custom=True)

    evil_content = "a" * 100 + "b"

    with patch(
        "guard_core.handlers._suspatterns_regex.shared_regex_executor"
    ) as mock_shared_executor:
        mock_future: concurrent.futures.Future[None] = concurrent.futures.Future()
        mock_future.set_exception(concurrent.futures.TimeoutError())
        mock_shared_executor.return_value.submit.return_value = mock_future

        with patch("guard_core.handlers._suspatterns_regex.logger") as mock_logger:
            result = await manager.detect(evil_content, "127.0.0.1", "test_timeout")

            assert result["is_threat"] is True
            assert any(
                threat["type"] == "pattern_timeout" for threat in result["threats"]
            )

            mock_logger.warning.assert_called()
            warning_msg = mock_logger.warning.call_args[0][0]
            assert "Regex timeout exceeded" in warning_msg

    manager._compiler = original_compiler
    await manager.remove_pattern(evil_pattern, custom=True)
    SusPatternsManager._instance = None


@pytest.mark.asyncio
async def test_regex_search_success_fallback() -> None:
    SusPatternsManager._instance = None
    manager = SusPatternsManager()

    original_compiler = manager._compiler
    manager._compiler = None

    test_pattern = r"test_pattern_\d+"
    await manager.add_pattern(test_pattern, custom=True)

    test_content = "This contains test_pattern_123 in it"

    matched, pattern = await manager.detect_pattern_match(
        test_content, "127.0.0.1", "test_search"
    )

    assert matched is True
    assert pattern == test_pattern

    manager._compiler = original_compiler
    await manager.remove_pattern(test_pattern, custom=True)
    SusPatternsManager._instance = None


@pytest.mark.asyncio
async def test_get_performance_stats_none() -> None:
    SusPatternsManager._instance = None
    manager = SusPatternsManager()

    original_monitor = manager._performance_monitor
    manager._performance_monitor = None

    stats = await manager.get_performance_stats()

    assert stats is None

    manager._performance_monitor = original_monitor
    SusPatternsManager._instance = None


@pytest.mark.asyncio
async def test_get_performance_stats_with_monitor(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    manager = sus_patterns_manager_with_detection

    stats = await manager.get_performance_stats()
    assert stats is not None


@pytest.mark.asyncio
async def test_pattern_timeout_with_compiler(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    manager = sus_patterns_manager_with_detection

    custom_pattern = r"timeout_sim_pattern"
    await manager.add_pattern(custom_pattern, custom=True)

    evil_content = "a" * 1000 + "b"

    current_time = 0.0

    def mock_time() -> float:
        nonlocal current_time
        current_time += 2.0
        return current_time

    with patch.object(manager._compiler, "create_safe_matcher") as mock_create:
        mock_matcher = MagicMock(return_value=None)
        mock_create.return_value = mock_matcher

        with patch("time.monotonic", mock_time):
            with patch("guard_core.handlers._suspatterns_regex.logger") as mock_logger:
                result = await manager.detect(evil_content, "127.0.0.1", "test_timeout")

                warning_calls = [
                    call[0][0] for call in mock_logger.warning.call_args_list
                ]
                timeout_warnings = [
                    msg for msg in warning_calls if "Pattern timeout:" in msg
                ]
                assert len(timeout_warnings) > 0

                assert len(result["timeouts"]) > 0

    await manager.remove_pattern(custom_pattern, custom=True)


@pytest.mark.asyncio
async def test_pattern_timeout_preserves_existing_regex_threat(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    manager = sus_patterns_manager_with_detection
    custom_pattern = r"timeout_with_existing_threat"
    await manager.add_pattern(custom_pattern, custom=True)
    existing_threat = {
        "type": "regex",
        "pattern": custom_pattern,
        "match": custom_pattern,
        "position": 0,
        "execution_time": 0.01,
        "category": "custom",
        "weight": 1,
    }

    async def fake_check(
        pattern: re.Pattern,
        content: str,
        ip_address: str,
        pattern_start: float,
        category: str,
        *,
        state: object = None,
        context: str = "unknown",
        binary_prefix: list[int] | None = None,
    ) -> tuple[dict | None, bool]:
        if pattern.pattern == custom_pattern:
            return dict(existing_threat), True
        return None, False

    with patch.object(manager, "_check_regex_pattern", new=fake_check):
        threats, matched, timeouts = await manager._check_regex_patterns(
            custom_pattern, "127.0.0.1", None, context="test"
        )

    assert custom_pattern in timeouts
    assert custom_pattern in matched
    preserved = [
        t
        for t in threats
        if t.get("type") == "regex" and t.get("pattern") == custom_pattern
    ]
    assert preserved
    assert preserved[0]["match"] == custom_pattern
    assert not any(t.get("type") == "pattern_timeout" for t in threats)

    await manager.remove_pattern(custom_pattern, custom=True)


@pytest.mark.asyncio
async def test_custom_category_timeout_heuristic_uses_configured_compiler_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    SusPatternsManager._instance = None
    config = SecurityConfig(detection_compiler_timeout=0.5)
    manager = SusPatternsManager(config)
    assert manager._compiler is not None
    assert manager._compiler.default_timeout == 0.5

    def _never_matches(
        pattern: object, timeout: float | None = None
    ) -> Callable[[str], None]:
        return lambda text: None

    monkeypatch.setattr(manager._compiler, "create_safe_matcher", _never_matches)
    monkeypatch.setattr(
        "guard_core.handlers.suspatterns_handler.time.monotonic", lambda: 100.5
    )

    pattern = re.compile(r"zzz_custom_zzz")
    _, timed_out = await manager._check_regex_pattern(
        pattern, "no match here", "1.2.3.4", 100.0, "custom"
    )

    assert timed_out is True

    SusPatternsManager._instance = None


@pytest.mark.asyncio
async def test_legacy_pattern_timeout_uses_configured_compiler_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    SusPatternsManager._instance = None
    manager = SusPatternsManager()
    assert manager._compiler is None
    manager._config = MagicMock(detection_compiler_timeout=7.5)

    captured_timeouts: list[float] = []

    async def fake_await(future: object, timeout: float) -> None:
        captured_timeouts.append(timeout)
        raise concurrent.futures.TimeoutError()

    with (
        patch(
            "guard_core.handlers._suspatterns_regex._await_regex_future",
            side_effect=fake_await,
        ),
        patch("guard_core.handlers._suspatterns_regex.shared_regex_executor"),
    ):
        match, timed_out = await manager._check_pattern_with_timeout(
            re.compile("x"), "content", "1.2.3.4", 0.0
        )

    assert match is None
    assert timed_out is True
    assert captured_timeouts == [7.5]

    SusPatternsManager._instance = None


@pytest.mark.asyncio
async def test_regex_search_exception_fallback() -> None:
    SusPatternsManager._instance = None
    manager = SusPatternsManager()

    original_compiler = manager._compiler
    manager._compiler = None

    test_pattern = r"test_pattern"
    await manager.add_pattern(test_pattern, custom=True)

    with patch(
        "guard_core.handlers._suspatterns_regex.shared_regex_executor"
    ) as mock_shared_executor:
        mock_future: concurrent.futures.Future[None] = concurrent.futures.Future()
        mock_future.set_exception(RuntimeError("Test exception"))
        mock_shared_executor.return_value.submit.return_value = mock_future

        with patch("guard_core.handlers._suspatterns_regex.logger") as mock_logger:
            result = await manager.detect("test content", "127.0.0.1", "test_exception")

            assert not result["is_threat"]

            mock_logger.error.assert_called()
            error_msg = mock_logger.error.call_args[0][0]
            assert "Error in regex search" in error_msg

    manager._compiler = original_compiler
    await manager.remove_pattern(test_pattern, custom=True)
    SusPatternsManager._instance = None


@pytest.mark.asyncio
async def test_semantic_threat_detection(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    manager = sus_patterns_manager_with_detection

    assert manager._semantic_analyzer is not None

    with patch.object(manager._semantic_analyzer, "analyze") as mock_analyze:
        with patch.object(manager._semantic_analyzer, "get_threat_score") as mock_score:
            semantic_analysis = {
                "attack_probabilities": {
                    "sql_injection": 0.85,
                    "xss": 0.65,
                    "command_injection": 0.45,
                },
                "tokens": ["SELECT", "*", "FROM", "users"],
                "suspicious_patterns": ["sql_keywords"],
            }
            mock_analyze.return_value = semantic_analysis
            mock_score.return_value = 0.85

            await manager.configure_semantic_threshold(0.7)

            result = await manager.detect(
                "SELECT * FROM users WHERE id=1", "127.0.0.1", "test_semantic"
            )

            assert result["is_threat"]
            assert result["threat_score"] >= 0.85

            semantic_threats = [t for t in result["threats"] if t["type"] == "semantic"]
            assert len(semantic_threats) >= 1

            attack_types = [t["attack_type"] for t in semantic_threats]
            assert "sql_injection" in attack_types


@pytest.mark.asyncio
async def test_semantic_threat_suspicious_fallback(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    manager = sus_patterns_manager_with_detection

    with patch.object(manager._semantic_analyzer, "analyze") as mock_analyze:
        with patch.object(manager._semantic_analyzer, "get_threat_score") as mock_score:
            semantic_analysis = {
                "attack_probabilities": {
                    "sql_injection": 0.4,
                    "xss": 0.3,
                    "command_injection": 0.2,
                },
                "suspicious_patterns": ["multiple_keywords"],
            }
            mock_analyze.return_value = semantic_analysis
            mock_score.return_value = 0.75

            await manager.configure_semantic_threshold(0.7)

            result = await manager.detect(
                "Suspicious content with multiple patterns",
                "127.0.0.1",
                "test_suspicious",
            )

            assert result["is_threat"]

            semantic_threats = [t for t in result["threats"] if t["type"] == "semantic"]
            assert len(semantic_threats) == 1

            assert semantic_threats[0]["attack_type"] == "suspicious"
            assert semantic_threats[0]["threat_score"] == 0.75


@pytest.mark.asyncio
async def test_semantic_analysis_skipped_for_binary_content(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    manager = sus_patterns_manager_with_detection

    with patch.object(manager._semantic_analyzer, "analyze") as mock_analyze:
        binary_blob = (bytes(range(256)) * 20).decode("utf-8", errors="replace")

        result = await manager.detect(binary_blob, "127.0.0.1", "test_binary")

        mock_analyze.assert_not_called()
        semantic_threats = [t for t in result["threats"] if t["type"] == "semantic"]
        assert semantic_threats == []


@pytest.mark.asyncio
async def test_legacy_detect_semantic_threat(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    manager = sus_patterns_manager_with_detection

    with patch.object(manager, "detect") as mock_detect:
        mock_detect.return_value = {
            "is_threat": True,
            "threats": [
                {"type": "semantic", "attack_type": "sql_injection", "probability": 0.9}
            ],
        }

        matched, pattern = await manager.detect_pattern_match(
            "test content", "127.0.0.1", "test"
        )

        assert matched is True
        assert pattern == "semantic:sql_injection"


@pytest.mark.asyncio
async def test_legacy_detect_unknown_threat(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    manager = sus_patterns_manager_with_detection

    with patch.object(manager, "detect") as mock_detect:
        mock_detect.return_value = {
            "is_threat": True,
            "threats": [{"type": "unknown_type", "data": "some_data"}],
        }

        matched, pattern = await manager.detect_pattern_match(
            "test content", "127.0.0.1", "test"
        )

        assert matched is True
        assert pattern == "unknown"


@pytest.mark.asyncio
async def test_compiler_cache_clearing_on_pattern_operations(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    manager = sus_patterns_manager_with_detection

    assert manager._compiler is not None

    with patch.object(manager._compiler, "clear_cache") as mock_clear:
        test_pattern = r"cache_test_pattern"
        await manager.add_pattern(test_pattern, custom=True)

        mock_clear.assert_called_once()

        mock_clear.reset_mock()

        result = await manager.remove_pattern(test_pattern, custom=True)
        assert result is True

        mock_clear.assert_called_once()

    if manager._performance_monitor:
        with patch.object(
            manager._performance_monitor, "remove_pattern_stats"
        ) as mock_remove:
            pattern_to_remove = manager.patterns[0]
            await manager.remove_pattern(pattern_to_remove, custom=False)

            mock_remove.assert_called_once_with(pattern_to_remove)


@pytest.mark.asyncio
async def test_detect_semantic_only_pattern_info(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    manager = sus_patterns_manager_with_detection

    with patch.object(manager._semantic_analyzer, "analyze") as mock_analyze:
        with patch.object(manager._semantic_analyzer, "get_threat_score") as mock_score:
            mock_analyze.return_value = {"attack_probabilities": {"xss": 0.9}}
            mock_score.return_value = 0.9

            mock_agent = MagicMock()
            manager.agent_handler = mock_agent

            result = await manager.detect(
                "semantic only threat", "127.0.0.1", "test_semantic_info"
            )

            assert result["is_threat"]


@pytest.mark.asyncio
async def test_get_component_status() -> None:
    original_instance = SusPatternsManager._instance

    try:
        SusPatternsManager._instance = None
        manager = SusPatternsManager()

        status = await manager.get_component_status()
        assert status["compiler"] is False
        assert status["preprocessor"] is False
        assert status["semantic_analyzer"] is False
        assert status["performance_monitor"] is False
    finally:
        SusPatternsManager._instance = original_instance


_SENSITIVE_FILE_PATTERNS = [
    r"(?:^|/)\.env(?:\.\w+)?(?:\?|$|/)",
    r"(?:^|/)[\w-]*config[\w-]*\."
    r"(?:env|yml|yaml|json|toml|ini|xml|conf)(?:\?|$)",
    r"(?:^|/)[\w./-]*\.map(?:\?|$)",
    r"(?:^|/)[\w./-]*\."
    r"(?:ts|tsx|jsx|py|rb|java|go|rs|php|pl|sh|sql)(?:\?|$)",
    r"(?:^|/)\.(?:git|svn|hg|bzr)(?:/|$)",
    r"(?:^|/)(?:wp-(?:admin|login|content|includes|config)"
    r"|administrator|xmlrpc)\.?(?:php)?(?:/|$|\?)",
    r"(?:^|/)(?:phpinfo|info|test|php_info)\.php(?:\?|$)",
    r"(?:^|/)[\w./-]*\."
    r"(?:bak|backup|old|orig|save|swp|swo|tmp|temp)(?:\?|$)",
    r"(?:^|/)(?:\.htaccess|\.htpasswd|\.DS_Store|Thumbs\.db"
    r"|\.npmrc|\.dockerenv|web\.config)(?:\?|$)",
]

_COMPILED_SENSITIVE_PATTERNS = [
    re.compile(p, re.IGNORECASE | re.MULTILINE) for p in _SENSITIVE_FILE_PATTERNS
]


def _matches_sensitive_pattern(path: str) -> bool:
    return any(p.search(path) for p in _COMPILED_SENSITIVE_PATTERNS)


@pytest.mark.parametrize(
    "path",
    [
        "/.env",
        "/.env.local",
        "/.env.production",
        "/.env.backup",
        "/app/.env",
        "/app/.env.dev",
    ],
    ids=lambda p: f"dotenv:{p}",
)
def test_sensitive_pattern_dotenv(path: str) -> None:
    assert _matches_sensitive_pattern(path), f"Expected match for dotenv path: {path}"


@pytest.mark.parametrize(
    "path",
    [
        "/config.yml",
        "/config.yaml",
        "/config.json",
        "/config.toml",
        "/config.ini",
        "/config.xml",
        "/config.conf",
        "/config.env",
        "/app-config.yml",
        "/db-config.json",
        "/server-config.toml",
    ],
    ids=lambda p: f"config:{p}",
)
def test_sensitive_pattern_config_files(path: str) -> None:
    assert _matches_sensitive_pattern(path), f"Expected match for config path: {path}"


@pytest.mark.parametrize(
    "path",
    [
        "/main.js.map",
        "/app.css.map",
        "/vendor.js.map",
        "/static/js/main.abc123.js.map",
    ],
    ids=lambda p: f"sourcemap:{p}",
)
def test_sensitive_pattern_source_maps(path: str) -> None:
    assert _matches_sensitive_pattern(path), f"Expected match for source map: {path}"


@pytest.mark.parametrize(
    "path",
    [
        "/app.py",
        "/main.ts",
        "/component.tsx",
        "/handler.go",
        "/server.rb",
        "/index.php",
        "/script.sh",
        "/dump.sql",
        "/Main.java",
        "/lib.rs",
    ],
    ids=lambda p: f"source:{p}",
)
def test_sensitive_pattern_source_code(path: str) -> None:
    assert _matches_sensitive_pattern(path), f"Expected match for source code: {path}"


@pytest.mark.parametrize(
    "path",
    [
        "/.git/config",
        "/.git/HEAD",
        "/.svn/entries",
        "/.hg/store",
        "/.bzr/README",
    ],
    ids=lambda p: f"vcs:{p}",
)
def test_sensitive_pattern_vcs_metadata(path: str) -> None:
    assert _matches_sensitive_pattern(path), f"Expected match for VCS path: {path}"


@pytest.mark.parametrize(
    "path",
    [
        "/wp-admin/",
        "/wp-login.php",
        "/wp-content/uploads/",
        "/wp-includes/",
        "/wp-config.php",
        "/administrator/",
        "/xmlrpc.php",
    ],
    ids=lambda p: f"cms:{p}",
)
def test_sensitive_pattern_cms_probing(path: str) -> None:
    assert _matches_sensitive_pattern(path), f"Expected match for CMS path: {path}"


@pytest.mark.parametrize(
    "path",
    [
        "/phpinfo.php",
        "/info.php",
        "/test.php",
        "/php_info.php",
    ],
    ids=lambda p: f"phpinfo:{p}",
)
def test_sensitive_pattern_php_info(path: str) -> None:
    assert _matches_sensitive_pattern(path), f"Expected match for PHP info: {path}"


@pytest.mark.parametrize(
    "path",
    [
        "/config.bak",
        "/database.backup",
        "/main.py.old",
        "/settings.orig",
        "/app.save",
        "/index.swp",
        "/data.tmp",
        "/backup.temp",
    ],
    ids=lambda p: f"backup:{p}",
)
def test_sensitive_pattern_backup_files(path: str) -> None:
    assert _matches_sensitive_pattern(path), f"Expected match for backup: {path}"


@pytest.mark.parametrize(
    "path",
    [
        "/.htaccess",
        "/.htpasswd",
        "/.DS_Store",
        "/Thumbs.db",
        "/.npmrc",
        "/.dockerenv",
        "/web.config",
    ],
    ids=lambda p: f"serverconfig:{p}",
)
def test_sensitive_pattern_server_configs(path: str) -> None:
    assert _matches_sensitive_pattern(path), f"Expected match for server config: {path}"


@pytest.mark.parametrize(
    "path",
    [
        "/config",
        "/settings",
        "/health",
        "/api/v1/users",
        "/map",
        "/environment",
        "/v1/config",
        "/blocking/config",
        "/stripe/config",
        "/payment/config",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/ip",
        "/custom-metrics",
        "/auth/jwt/login",
        "/patterns",
        "/patterns/add",
        "/project-stats",
        "/basic",
        "/quick-test",
        "/metrics",
        "/api/domains",
        "/api/search",
        "/api/changes",
    ],
    ids=lambda p: f"legitimate:{p}",
)
def test_sensitive_pattern_no_false_positives(path: str) -> None:
    assert not _matches_sensitive_pattern(path), (
        f"False positive: legitimate path matched: {path}"
    )


async def test_send_threat_event_with_no_patterns_uses_unknown_label() -> None:
    # Defensive path: detect() only calls this when is_threat=True, which implies
    # either matched_patterns or semantic_threats is non-empty. Invoke directly
    # with both empty to exercise the "unknown" fallback branch.
    from guard_core.handlers.suspatterns_handler import SusPatternsManager

    SusPatternsManager._instance = None
    mgr = SusPatternsManager()
    mgr.agent_handler = None  # skip event dispatch
    await mgr._send_threat_event(
        matched_patterns=[],
        semantic_threats=[],
        ip_address="1.2.3.4",
        context="unknown",
        content="",
        threat_score=0.0,
        threats=[],
        regex_threats=[],
        timeouts=[],
        execution_time=0.0,
        correlation_id=None,
    )


async def test_add_custom_pattern_writes_to_redis_when_configured() -> None:
    from unittest.mock import AsyncMock

    from guard_core.handlers.suspatterns_handler import SusPatternsManager

    SusPatternsManager._instance = None
    mgr = SusPatternsManager()
    redis_handler = AsyncMock()
    redis_handler.set_key = AsyncMock()
    mgr.redis_handler = redis_handler

    await mgr.add_pattern(r"custom_test_redis_add", custom=True)
    redis_handler.set_key.assert_called()


async def test_remove_custom_pattern_writes_to_redis_when_configured() -> None:
    from unittest.mock import AsyncMock

    from guard_core.handlers.suspatterns_handler import SusPatternsManager

    SusPatternsManager._instance = None
    mgr = SusPatternsManager()
    await mgr.add_pattern(r"custom_test_redis_remove", custom=True)

    redis_handler = AsyncMock()
    redis_handler.set_key = AsyncMock()
    mgr.redis_handler = redis_handler

    assert await mgr._remove_custom_pattern(r"custom_test_redis_remove") is True
    redis_handler.set_key.assert_called()


async def test_initialize_redis_with_cached_patterns_empty() -> None:
    from unittest.mock import AsyncMock

    from guard_core.handlers.suspatterns_handler import SusPatternsManager

    SusPatternsManager._instance = None
    mgr = SusPatternsManager()
    redis_handler = AsyncMock()
    redis_handler.get_key = AsyncMock(return_value=None)
    await mgr.initialize_redis(redis_handler)
    assert mgr.redis_handler is redis_handler


async def test_initialize_redis_skips_patterns_already_in_custom() -> None:
    from unittest.mock import AsyncMock

    from guard_core.handlers.suspatterns_handler import SusPatternsManager

    SusPatternsManager._instance = None
    mgr = SusPatternsManager()
    mgr.custom_patterns.add("existing_pattern")
    redis_handler = AsyncMock()
    redis_handler.get_key = AsyncMock(return_value="existing_pattern")
    await mgr.initialize_redis(redis_handler)
    assert "existing_pattern" in mgr.custom_patterns


async def test_initialize_redis_logs_and_returns_when_get_key_raises() -> None:
    from unittest.mock import AsyncMock

    from guard_core.exceptions import GuardRedisError
    from guard_core.handlers.suspatterns_handler import SusPatternsManager

    SusPatternsManager._instance = None
    mgr = SusPatternsManager()
    redis_handler = AsyncMock()
    redis_handler.get_key = AsyncMock(
        side_effect=GuardRedisError(503, "redis unavailable")
    )
    await mgr.initialize_redis(redis_handler)
    assert mgr.redis_handler is redis_handler


async def test_initialize_redis_warns_on_rejected_persisted_pattern(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from unittest.mock import AsyncMock

    from guard_core.handlers.suspatterns_handler import SusPatternsManager

    SusPatternsManager._instance = None
    mgr = SusPatternsManager()
    redis_handler = AsyncMock()
    redis_handler.get_key = AsyncMock(return_value="invalid(regex")

    with caplog.at_level(logging.WARNING):
        await mgr.initialize_redis(redis_handler)

    assert "invalid(regex" not in mgr.custom_patterns
    assert "Skipped restoring persisted pattern" in caplog.text


async def test_detect_pattern_match_with_unknown_threat_type_returns_unknown() -> None:
    from unittest.mock import AsyncMock

    from guard_core.handlers.suspatterns_handler import SusPatternsManager

    SusPatternsManager._instance = None
    mgr = SusPatternsManager()
    mgr.detect = AsyncMock(  # type: ignore[method-assign]
        return_value={"is_threat": True, "threats": [{"type": "novel_kind"}]}
    )
    is_threat, label = await mgr.detect_pattern_match("content", "1.2.3.4")
    assert is_threat is True
    assert label == "unknown"


async def test_detect_pattern_match_empty_threats_list_returns_unknown() -> None:
    from unittest.mock import AsyncMock

    from guard_core.handlers.suspatterns_handler import SusPatternsManager

    SusPatternsManager._instance = None
    mgr = SusPatternsManager()
    mgr.detect = AsyncMock(  # type: ignore[method-assign]
        return_value={"is_threat": True, "threats": []}
    )
    is_threat, label = await mgr.detect_pattern_match("content", "1.2.3.4")
    assert is_threat is True
    assert label == "unknown"
    SusPatternsManager._instance = None


async def test_reset_noop_when_instance_is_none() -> None:
    from guard_core.handlers.suspatterns_handler import SusPatternsManager

    original = SusPatternsManager._instance
    SusPatternsManager._instance = None
    await SusPatternsManager.reset()
    SusPatternsManager._instance = original


async def test_reset_drops_a_populated_redis_handler_reference() -> None:
    from guard_core.handlers.suspatterns_handler import SusPatternsManager

    original = SusPatternsManager._instance
    SusPatternsManager._instance = None
    manager = SusPatternsManager()
    manager.redis_handler = AsyncMock()
    manager.agent_handler = AsyncMock()

    await SusPatternsManager.reset()

    assert manager.redis_handler is None
    assert manager.agent_handler is None
    SusPatternsManager._instance = original


@pytest.mark.asyncio
async def test_custom_pattern_match_rejected_by_validator_falls_through(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    from guard_core.handlers.suspatterns_handler import _GLUED_BACKTICK_CANDIDATE_RE

    manager = sus_patterns_manager_with_detection
    pattern = re.compile(_GLUED_BACKTICK_CANDIDATE_RE, re.IGNORECASE)

    threat, timed_out = await manager._check_regex_pattern(
        pattern, "`whoami`", "1.2.3.4", time.monotonic(), "custom"
    )

    assert threat is None
    assert timed_out is False


@pytest.mark.asyncio
async def test_configure_with_unsupported_config_is_a_noop() -> None:
    SusPatternsManager._instance = None
    manager = SusPatternsManager()
    state_before = manager._detection_state

    manager.configure(object())

    assert manager._detection_state is state_before
    SusPatternsManager._instance = None


@pytest.mark.asyncio
async def test_initialize_agent_sets_agent_handler() -> None:
    SusPatternsManager._instance = None
    manager = SusPatternsManager()
    agent = object()

    await manager.initialize_agent(agent)

    assert manager.agent_handler is agent
    SusPatternsManager._instance = None


@pytest.mark.asyncio
async def test_add_pattern_sends_event_when_agent_handler_set() -> None:
    mock_agent = MagicMock()
    mock_agent.send_event = AsyncMock()
    sus_patterns_handler.agent_handler = mock_agent
    pattern = r"agent_event_add_pattern_xyz"

    try:
        await sus_patterns_handler.add_pattern(pattern, custom=True)

        mock_agent.send_event.assert_called_once()
    finally:
        sus_patterns_handler.agent_handler = None
        await sus_patterns_handler.remove_pattern(pattern, custom=True)


@pytest.mark.asyncio
async def test_remove_pattern_sends_event_when_agent_handler_set() -> None:
    pattern = r"agent_event_remove_pattern_xyz"
    await sus_patterns_handler.add_pattern(pattern, custom=True)
    mock_agent = MagicMock()
    mock_agent.send_event = AsyncMock()
    sus_patterns_handler.agent_handler = mock_agent

    try:
        result = await sus_patterns_handler.remove_pattern(pattern, custom=True)

        assert result is True
        mock_agent.send_event.assert_called_once()
    finally:
        sus_patterns_handler.agent_handler = None


@pytest.mark.asyncio
async def test_remove_default_pattern_returns_false_when_not_found() -> None:
    result = await sus_patterns_handler.remove_pattern(
        "nonexistent_default_pattern_xyz", custom=False
    )
    assert result is False


@pytest.mark.asyncio
async def test_remove_default_pattern_returns_false_when_compiled_index_missing() -> (
    None
):
    handler = sus_patterns_handler
    original_patterns = handler.patterns.copy()
    original_compiled = handler.compiled_patterns.copy()

    try:
        test_pattern = "test_pattern_compiled_index_missing_xyz"
        handler.patterns.append(test_pattern)
        handler.compiled_patterns = []

        result = await handler._remove_default_pattern(test_pattern)

        assert result is False
    finally:
        handler.patterns = original_patterns
        handler.compiled_patterns = original_compiled
