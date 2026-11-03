import json
import logging
from collections.abc import Iterator, Mapping
from typing import Any, Protocol, runtime_checkable
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core._utils.detection_scan import _json_depth_cap_value
from guard_core.core.checks import build_default_pipeline
from guard_core.core.events.middleware_events import SecurityEventBus
from guard_core.handlers.ratelimit_handler import RateLimitManager
from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

_SQLI_PAYLOAD = "' OR 1=1--"
_CUSTOM_SECRET_PATTERN = "password=hunter2ThisIsASecretXYZ"
_CUSTOM_SECRET_LITERAL = "hunter2ThisIsASecretXYZ"


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


@pytest.fixture
def mock_agent() -> Iterator[MagicMock]:
    agent = MagicMock()
    agent.send_event = AsyncMock()
    sus_patterns_handler.agent_handler = agent
    try:
        yield agent
    finally:
        sus_patterns_handler.agent_handler = None


def _json_request(body: bytes) -> MockGuardRequest:
    return MockGuardRequest(
        method="POST",
        client_host="127.0.0.1",
        body_content=body,
        headers={
            "content-type": "application/json",
            "content-length": str(len(body)),
        },
    )


def _nested_wrapper_body(depth: int, wrapper_key: str, leaf: dict) -> bytes:
    leaf_json = json.dumps(leaf)
    prefix = f'{{"{wrapper_key}":' * depth
    suffix = "}" * depth
    return (prefix + leaf_json + suffix).encode()


@runtime_checkable
class _PatternDetectedEvent(Protocol):
    handler_name: str
    pattern_matched: str
    reason: str
    metadata: Mapping[str, str | list[str]]


def _single_threat_event_metadata(mock_agent: MagicMock) -> dict[str, Any]:
    pattern_detected_calls = [
        call
        for call in mock_agent.send_event.call_args_list
        if getattr(call.args[0], "event_type", None) == "pattern_detected"
    ]
    assert len(pattern_detected_calls) == 1, (
        f"expected exactly one pattern_detected event, "
        f"got {len(pattern_detected_calls)}"
    )
    return dict(pattern_detected_calls[0].args[0].metadata)


async def test_sensitive_header_threat_event_content_preview_redacted(
    mock_agent: MagicMock,
) -> None:
    config = SecurityConfig(log_sensitive_headers={"x-session"})
    secret = "tok-SECRET-EVENT"
    request = MockGuardRequest(
        headers={"X-Session": f"{secret} <script>alert(1)</script>"},
    )

    result = await detect_penetration_attempt(request, config)

    assert result.is_threat is True
    metadata = _single_threat_event_metadata(mock_agent)
    assert metadata["content_preview"] == "[REDACTED]"
    assert secret not in json.dumps(metadata, default=str)


async def test_sensitive_query_param_threat_event_content_preview_redacted(
    mock_agent: MagicMock,
) -> None:
    config = SecurityConfig()
    secret = "SECRET-EVENT-Q"
    request = MockGuardRequest(
        query_params={"token": f"{secret} <script>alert(1)</script>"},
    )

    result = await detect_penetration_attempt(request, config)

    assert result.is_threat is True
    metadata = _single_threat_event_metadata(mock_agent)
    assert metadata["content_preview"] == "[REDACTED]"
    assert secret not in json.dumps(metadata, default=str)


_EMBEDDED_JSON_SECRET = "SECRET-EMB"
_EMBEDDED_JSON_PAYLOAD = json.dumps(
    {"q": "<script>alert(1)</script>", "tok": _EMBEDDED_JSON_SECRET}
)


async def test_sensitive_header_embedded_json_field_content_preview_redacted(
    mock_agent: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(log_sensitive_headers={"x-session"})
    request = MockGuardRequest(headers={"X-Session": _EMBEDDED_JSON_PAYLOAD})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = await detect_penetration_attempt(request, config)

    assert result.is_threat is True
    metadata = _single_threat_event_metadata(mock_agent)
    assert metadata["content_preview"] == "[REDACTED]"
    assert _EMBEDDED_JSON_SECRET not in json.dumps(metadata, default=str)
    assert _EMBEDDED_JSON_SECRET not in caplog.text


async def test_sensitive_query_param_embedded_json_field_content_preview_redacted(
    mock_agent: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig()
    request = MockGuardRequest(query_params={"token": _EMBEDDED_JSON_PAYLOAD})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = await detect_penetration_attempt(request, config)

    assert result.is_threat is True
    metadata = _single_threat_event_metadata(mock_agent)
    assert metadata["content_preview"] == "[REDACTED]"
    assert _EMBEDDED_JSON_SECRET not in json.dumps(metadata, default=str)
    assert _EMBEDDED_JSON_SECRET not in caplog.text


async def test_non_sensitive_header_embedded_json_field_content_preview_is_raw(
    mock_agent: MagicMock,
) -> None:
    config = SecurityConfig()
    request = MockGuardRequest(headers={"X-Custom": _EMBEDDED_JSON_PAYLOAD})

    result = await detect_penetration_attempt(request, config)

    assert result.is_threat is True
    metadata = _single_threat_event_metadata(mock_agent)
    assert metadata["content_preview"] == "<script>alert(1)</script>"


def _single_threat_event(mock_agent: MagicMock) -> _PatternDetectedEvent:
    pattern_detected_calls = [
        call
        for call in mock_agent.send_event.call_args_list
        if getattr(call.args[0], "event_type", None) == "pattern_detected"
    ]
    assert len(pattern_detected_calls) == 1, (
        f"expected exactly one pattern_detected event, "
        f"got {len(pattern_detected_calls)}"
    )
    event = pattern_detected_calls[0].args[0]
    assert isinstance(event, _PatternDetectedEvent)
    return event


_EMBEDDED_JSON_SECRET_KEY = "SECRET-KEY-<script>alert(1)</script>"


async def test_sensitive_query_param_embedded_json_key_redacted_in_reason(
    mock_agent: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(log_sensitive_params={"tok"})
    payload = json.dumps({_EMBEDDED_JSON_SECRET_KEY: "benign"})
    request = MockGuardRequest(query_params={"tok": payload})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = await detect_penetration_attempt(request, config)

    assert result.is_threat is True
    event = _single_threat_event(mock_agent)
    dumped_metadata = json.dumps(dict(event.metadata), default=str)
    assert "SECRET-KEY" not in event.reason
    assert "SECRET-KEY" not in dumped_metadata
    assert "SECRET-KEY" not in caplog.text
    assert "[REDACTED]" in event.reason
    assert "[REDACTED]" in dumped_metadata


async def test_sensitive_header_embedded_json_key_redacted_in_reason(
    mock_agent: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(log_sensitive_headers={"x-session"})
    payload = json.dumps({_EMBEDDED_JSON_SECRET_KEY: "benign"})
    request = MockGuardRequest(headers={"X-Session": payload})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = await detect_penetration_attempt(request, config)

    assert result.is_threat is True
    event = _single_threat_event(mock_agent)
    dumped_metadata = json.dumps(dict(event.metadata), default=str)
    assert "SECRET-KEY" not in event.reason
    assert "SECRET-KEY" not in dumped_metadata
    assert "SECRET-KEY" not in caplog.text
    assert "[REDACTED]" in event.reason
    assert "[REDACTED]" in dumped_metadata


async def test_non_sensitive_query_param_embedded_json_key_reports_raw_key_in_context(
    mock_agent: MagicMock,
) -> None:
    config = SecurityConfig()
    payload = json.dumps({_EMBEDDED_JSON_SECRET_KEY: "benign"})
    request = MockGuardRequest(query_params={"q": payload})

    result = await detect_penetration_attempt(request, config)

    assert result.is_threat is True
    metadata = _single_threat_event_metadata(mock_agent)
    assert _EMBEDDED_JSON_SECRET_KEY in metadata["context"]


async def test_sensitive_body_field_threat_event_content_preview_redacted(
    mock_agent: MagicMock,
) -> None:
    config = SecurityConfig()
    secret = "SECRET-EVENT-BODY"
    body = json.dumps({"password": f"{secret} {_SQLI_PAYLOAD}"}).encode()

    result = await detect_penetration_attempt(_json_request(body), config)

    assert result.is_threat is True
    metadata = _single_threat_event_metadata(mock_agent)
    assert metadata["content_preview"] == "[REDACTED]"
    assert secret not in json.dumps(metadata, default=str)


async def test_non_sensitive_query_param_embedded_json_sensitive_field_preview_redacted(
    mock_agent: MagicMock,
) -> None:
    config = SecurityConfig()
    secret = "SECRET-EMBEDDED-FIELD"
    body = json.dumps({"password": f"{secret} {_SQLI_PAYLOAD}", "note": "benign"})
    request = MockGuardRequest(query_params={"data": body})

    result = await detect_penetration_attempt(request, config)

    assert result.is_threat is True
    metadata = _single_threat_event_metadata(mock_agent)
    assert metadata["content_preview"] == "[REDACTED]"
    assert secret not in json.dumps(metadata, default=str)


async def test_capped_json_subtree_threat_event_preview_matches_redacted_display(
    mock_agent: MagicMock,
) -> None:
    config = SecurityConfig()
    depth = _json_depth_cap_value() - 1
    secret = "SECRET-EVENT-NESTED"
    leaf = {"password": f"{secret} {_SQLI_PAYLOAD}"}
    body = _nested_wrapper_body(depth, "wrapper", leaf)

    result = await detect_penetration_attempt(_json_request(body), config)

    assert result.is_threat is True
    metadata = _single_threat_event_metadata(mock_agent)
    expected_display = json.dumps(
        {"password": "[REDACTED]"}, separators=(",", ":"), ensure_ascii=False
    )
    assert metadata["content_preview"] == expected_display
    assert secret not in json.dumps(metadata, default=str)


async def test_non_sensitive_query_param_threat_event_content_preview_is_raw(
    mock_agent: MagicMock,
) -> None:
    config = SecurityConfig()
    payload = "<script>alert(1)</script>"
    request = MockGuardRequest(query_params={"q": payload})

    result = await detect_penetration_attempt(request, config)

    assert result.is_threat is True
    metadata = _single_threat_event_metadata(mock_agent)
    assert metadata["content_preview"] == payload


async def test_non_sensitive_long_query_param_threat_event_content_preview_capped(
    mock_agent: MagicMock,
) -> None:
    config = SecurityConfig()
    payload = ("A" * 91) + _SQLI_PAYLOAD
    assert len(payload) > 100
    request = MockGuardRequest(query_params={"q": payload})

    result = await detect_penetration_attempt(request, config)

    assert result.is_threat is True
    metadata = _single_threat_event_metadata(mock_agent)
    assert metadata["content_preview"] == payload[:100]


async def test_detect_uses_content_preview_kwarg_over_raw_content_for_event(
    mock_agent: MagicMock,
) -> None:
    secret = "SECRET-DIRECT"
    payload = f"{secret} {_SQLI_PAYLOAD}"

    result = await sus_patterns_handler.detect(
        content=payload,
        ip_address="127.0.0.1",
        context="unit_test",
        content_preview="[REDACTED]",
    )

    assert result["is_threat"] is True
    metadata = _single_threat_event_metadata(mock_agent)
    assert metadata["content_preview"] == "[REDACTED]"
    assert secret not in json.dumps(metadata, default=str)


async def test_detect_content_preview_still_capped_at_100_chars(
    mock_agent: MagicMock,
) -> None:
    long_preview = "P" * 150

    result = await sus_patterns_handler.detect(
        content=_SQLI_PAYLOAD,
        ip_address="127.0.0.1",
        context="unit_test",
        content_preview=long_preview,
    )

    assert result["is_threat"] is True
    metadata = _single_threat_event_metadata(mock_agent)
    assert metadata["content_preview"] == "P" * 100


async def test_pattern_detected_event_sets_pattern_matched_and_category_for_regex_hit(
    mock_agent: MagicMock,
) -> None:
    config = SecurityConfig()
    request = MockGuardRequest(query_params={"q": _SQLI_PAYLOAD})

    result = await detect_penetration_attempt(request, config)

    assert result.is_threat is True
    event = _single_threat_event(mock_agent)
    assert event.handler_name == "sus_patterns"
    assert event.pattern_matched == event.metadata["pattern"]
    assert event.metadata["category"] == "sqli"
    assert event.metadata["threat_categories"] == ["sqli"]


async def test_pattern_detected_event_semantic_hit_sets_pattern_matched_and_category(
    mock_agent: MagicMock,
) -> None:
    assert sus_patterns_handler._semantic_analyzer is not None

    with patch.object(
        sus_patterns_handler._semantic_analyzer, "analyze"
    ) as mock_analyze:
        with patch.object(
            sus_patterns_handler._semantic_analyzer, "get_threat_score"
        ) as mock_score:
            mock_analyze.return_value = {"attack_probabilities": {"sql": 0.9}}
            mock_score.return_value = 0.9

            result = await sus_patterns_handler.detect(
                content="totally benign text with no special characters",
                ip_address="127.0.0.1",
                context="unit_test",
            )

    assert result["is_threat"] is True
    event = _single_threat_event(mock_agent)
    assert event.pattern_matched == "semantic:sql"
    assert event.handler_name == "sus_patterns"
    assert event.metadata["pattern"] == "semantic:sql"
    assert event.metadata["category"] == "sqli"
    assert event.metadata["threat_categories"] == ["sqli"]


async def test_pattern_detected_event_redacts_pattern_matched_for_custom_secret_pattern(
    mock_agent: MagicMock,
) -> None:
    config = SecurityConfig()
    await sus_patterns_handler.add_pattern("password=hunter2", custom=True)
    try:
        mock_agent.reset_mock()

        request = MockGuardRequest(headers={"X-Custom": "password=hunter2"})
        result = await detect_penetration_attempt(request, config)

        assert result.is_threat is True
        event = _single_threat_event(mock_agent)
        assert event.pattern_matched == "[REDACTED]"
        assert event.metadata["pattern"] == "[REDACTED]"
    finally:
        await sus_patterns_handler.remove_pattern("password=hunter2", custom=True)


async def test_pattern_detected_event_redacts_regex_separated_custom_secret_pattern(
    mock_agent: MagicMock,
) -> None:
    config = SecurityConfig()
    source = r"password\s*=\s*hunter2"
    await sus_patterns_handler.add_pattern(source, custom=True)
    try:
        mock_agent.reset_mock()

        request = MockGuardRequest(headers={"X-Custom": "password = hunter2"})
        result = await detect_penetration_attempt(request, config)

        assert result.is_threat is True
        assert "hunter2" not in result.trigger_info
        event = _single_threat_event(mock_agent)
        assert "hunter2" not in event.pattern_matched
        assert "hunter2" not in event.metadata["pattern"]
        assert "[REDACTED]" in event.pattern_matched
    finally:
        await sus_patterns_handler.remove_pattern(source, custom=True)


async def test_pattern_detected_event_metadata_pattern_matches_pattern_matched(
    mock_agent: MagicMock,
) -> None:
    config = SecurityConfig()
    await sus_patterns_handler.add_pattern(_CUSTOM_SECRET_PATTERN, custom=True)
    try:
        mock_agent.reset_mock()

        request = MockGuardRequest(headers={"X-Custom": _CUSTOM_SECRET_PATTERN})
        result = await detect_penetration_attempt(request, config)

        assert result.is_threat is True
        event = _single_threat_event(mock_agent)
        assert _CUSTOM_SECRET_LITERAL not in event.metadata["pattern"]
        assert _CUSTOM_SECRET_LITERAL not in event.pattern_matched
        assert event.metadata["pattern"] == event.pattern_matched
    finally:
        await sus_patterns_handler.remove_pattern(_CUSTOM_SECRET_PATTERN, custom=True)


async def test_pattern_detected_event_builtin_pattern_source_unchanged_in_metadata(
    mock_agent: MagicMock,
) -> None:
    config = SecurityConfig()
    request = MockGuardRequest(query_params={"q": _SQLI_PAYLOAD})

    result = await detect_penetration_attempt(request, config)

    assert result.is_threat is True
    event = _single_threat_event(mock_agent)

    all_patterns = await sus_patterns_handler.get_all_compiled_patterns()
    builtin_sources = {
        pattern.pattern for pattern, _contexts, _category in all_patterns
    }
    assert event.metadata["pattern"] in builtin_sources
    assert event.metadata["pattern"] == event.pattern_matched


async def test_send_threat_event_dedupes_and_skips_uncategorized_threat_categories(
    mock_agent: MagicMock,
) -> None:
    await sus_patterns_handler._send_threat_event(
        matched_patterns=["' OR 1=1--"],
        semantic_threats=[],
        ip_address="127.0.0.1",
        context="unit_test",
        content="' OR 1=1--",
        threat_score=1.0,
        threats=[
            {"type": "regex", "pattern": "' OR 1=1--", "category": "sqli"},
            {"type": "regex", "pattern": "' OR 2=2--", "category": "sqli"},
            {"type": "pattern_timeout", "pattern": "slow", "category": "sqli"},
        ],
        regex_threats=[],
        timeouts=[],
        execution_time=0.001,
        correlation_id="test-correlation",
    )

    event = _single_threat_event(mock_agent)
    assert event.metadata["threat_categories"] == ["sqli"]
    assert event.metadata["category"] == "sqli"


async def test_send_threat_event_maps_semantic_suspicious_fallback_to_custom_category(
    mock_agent: MagicMock,
) -> None:
    await sus_patterns_handler._send_threat_event(
        matched_patterns=[],
        semantic_threats=[{"type": "semantic", "attack_type": "suspicious"}],
        ip_address="127.0.0.1",
        context="unit_test",
        content="benign",
        threat_score=1.0,
        threats=[{"type": "semantic", "attack_type": "suspicious"}],
        regex_threats=[],
        timeouts=[],
        execution_time=0.001,
        correlation_id="test-correlation",
    )

    event = _single_threat_event(mock_agent)
    assert event.pattern_matched == "semantic:suspicious"
    assert event.metadata["threat_categories"] == ["custom"]
    assert event.metadata["category"] == "custom"


def test_semantic_attack_type_to_category_map_covers_every_analyzer_keyword() -> None:
    from guard_core.detection_engine.semantic import SemanticAnalyzer
    from guard_core.handlers.suspatterns_handler import (
        SEMANTIC_ATTACK_TYPE_TO_CATEGORY,
    )

    missing = set(SemanticAnalyzer().attack_keywords) - set(
        SEMANTIC_ATTACK_TYPE_TO_CATEGORY
    )
    assert not missing, f"semantic attack types missing a category mapping: {missing}"


def test_semantic_attack_type_to_category_map_targets_are_known_regex_categories() -> (
    None
):
    from guard_core.handlers._suspatterns_sources import ALL_DETECTION_CATEGORIES
    from guard_core.handlers.suspatterns_handler import (
        SEMANTIC_ATTACK_TYPE_TO_CATEGORY,
    )

    known = ALL_DETECTION_CATEGORIES | {"custom"}
    unknown = set(SEMANTIC_ATTACK_TYPE_TO_CATEGORY.values()) - known
    assert not unknown, f"category map targets are not real categories: {unknown}"


def _event_to_dict(event: object) -> dict[str, Any]:
    if hasattr(event, "model_dump"):
        return dict(event.model_dump(mode="json"))
    return dict(vars(event))


def _pipeline_middleware(config: SecurityConfig, agent: MagicMock) -> MagicMock:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger(
        "guard_core.test.detection_telemetry.pipeline"
    )
    middleware.event_bus = SecurityEventBus(
        agent_handler=agent, config=config, geo_ip_handler=None
    )
    middleware.create_error_response = AsyncMock(
        side_effect=lambda status_code, default_message: MagicMock(
            status_code=status_code
        )
    )
    middleware.route_resolver = MagicMock()
    middleware.route_resolver.get_route_config = MagicMock(return_value=None)
    middleware.route_resolver.should_bypass_check = MagicMock(return_value=False)
    middleware.route_resolver.get_cloud_providers_to_check = MagicMock(
        return_value=None
    )
    middleware.geo_ip_handler = None
    middleware.agent_handler = agent
    middleware.suspicious_request_counts = {}
    middleware.last_cloud_ip_refresh = 0
    middleware.refresh_cloud_ip_ranges = AsyncMock(return_value=None)
    middleware.rate_limit_handler = RateLimitManager(config)
    middleware.response_factory = MagicMock()
    middleware.response_factory.apply_modifier = AsyncMock(side_effect=lambda r: r)
    middleware.guard_decorator = None
    return middleware


async def _run_custom_secret_pattern_pipeline(
    mock_agent: MagicMock,
    caplog: pytest.LogCaptureFixture,
    *,
    passive_mode: bool,
) -> tuple[list[dict[str, Any]], Any]:
    on_block_calls: list[dict[str, Any]] = []

    def _on_block(request: object, payload: dict[str, Any]) -> None:
        on_block_calls.append(payload)

    config = SecurityConfig(
        passive_mode=passive_mode, on_block=_on_block, enable_ip_banning=False
    )
    await sus_patterns_handler.add_pattern(_CUSTOM_SECRET_PATTERN, custom=True)
    try:
        middleware = _pipeline_middleware(config, mock_agent)
        pipeline = build_default_pipeline(middleware)
        request = MockGuardRequest(
            headers={"X-Custom": _CUSTOM_SECRET_PATTERN},
            client_host="203.0.113.201",
        )
        request.state.client_ip = "203.0.113.201"

        with caplog.at_level(logging.WARNING, logger="guard_core"):
            response = await pipeline.execute(request)
    finally:
        await sus_patterns_handler.remove_pattern(_CUSTOM_SECRET_PATTERN, custom=True)

    return on_block_calls, response


async def test_custom_secret_pattern_redacted_on_active_block_trigger_info_and_on_block(
    mock_agent: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    on_block_calls, response = await _run_custom_secret_pattern_pipeline(
        mock_agent, caplog, passive_mode=False
    )

    assert response is not None
    assert _CUSTOM_SECRET_LITERAL not in caplog.text

    events_dump = json.dumps(
        [_event_to_dict(call.args[0]) for call in mock_agent.send_event.call_args_list],
        default=str,
    )
    assert mock_agent.send_event.call_args_list
    assert _CUSTOM_SECRET_LITERAL not in events_dump

    assert on_block_calls, "on_block was never invoked"
    on_block_dump = json.dumps(on_block_calls, default=str)
    assert _CUSTOM_SECRET_LITERAL not in on_block_dump
    assert "[REDACTED]" in on_block_dump
    assert "[REDACTED]" in on_block_calls[0]["reason"]


async def test_custom_secret_pattern_redacted_on_passive_mode_trigger_info_and_on_block(
    mock_agent: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    on_block_calls, response = await _run_custom_secret_pattern_pipeline(
        mock_agent, caplog, passive_mode=True
    )

    assert response is None
    assert _CUSTOM_SECRET_LITERAL not in caplog.text

    events_dump = json.dumps(
        [_event_to_dict(call.args[0]) for call in mock_agent.send_event.call_args_list],
        default=str,
    )
    assert mock_agent.send_event.call_args_list
    assert _CUSTOM_SECRET_LITERAL not in events_dump

    assert on_block_calls, "on_block was never invoked in passive mode"
    on_block_dump = json.dumps(on_block_calls, default=str)
    assert _CUSTOM_SECRET_LITERAL not in on_block_dump
    assert "[REDACTED]" in on_block_calls[0]["trigger_info"]
