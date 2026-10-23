import json
import logging
from collections.abc import Iterator
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_XSS = "<script>alert(1)</script>"


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


@pytest.fixture
def mock_agent() -> Iterator[MagicMock]:
    agent = MagicMock()
    agent.send_event = MagicMock()
    sus_patterns_handler.agent_handler = agent
    try:
        yield agent
    finally:
        sus_patterns_handler.agent_handler = None


def _attack_lines(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        line for line in caplog.text.splitlines() if "Potential attack detected" in line
    ]


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


def _surface_request(surface: str, value: str) -> SyncMockGuardRequest:
    if surface == "header":
        return SyncMockGuardRequest(headers={"X-Custom": value})
    if surface == "query_param":
        return SyncMockGuardRequest(query_params={"data": value})
    return SyncMockGuardRequest(path=value)


_SURFACES = ["header", "query_param", "url_path"]


@pytest.mark.parametrize("surface", _SURFACES)
def test_attack_in_non_sensitive_field_keeps_sibling_secret_redacted(
    surface: str, caplog: pytest.LogCaptureFixture, mock_agent: MagicMock
) -> None:
    secret = f"SIBLING-SECRET-{surface}"
    payload = json.dumps({"note": _XSS, "password": secret})
    request = _surface_request(surface, payload)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is True
    lines = _attack_lines(caplog)
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert _XSS in lines[0]
    assert secret not in caplog.text

    metadata = _single_threat_event_metadata(mock_agent)
    assert secret not in json.dumps(metadata, default=str)


@pytest.mark.parametrize("surface", _SURFACES)
def test_nested_two_levels_sensitive_key_redacted(
    surface: str, caplog: pytest.LogCaptureFixture, mock_agent: MagicMock
) -> None:
    secret = f"NESTED-SECRET-{surface}"
    payload = json.dumps({"user": {"password": f"{secret} {_XSS}"}})
    request = _surface_request(surface, payload)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is True
    lines = _attack_lines(caplog)
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert secret not in caplog.text

    metadata = _single_threat_event_metadata(mock_agent)
    assert secret not in json.dumps(metadata, default=str)


@pytest.mark.parametrize("surface", _SURFACES)
def test_object_under_sensitive_key_nested_nonsensitive_leaf_redacted(
    surface: str, caplog: pytest.LogCaptureFixture, mock_agent: MagicMock
) -> None:
    secret = f"OBJVAL-SECRET-{surface}"
    payload = json.dumps({"password": {"inner": f"{secret} {_XSS}"}})
    request = _surface_request(surface, payload)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is True
    lines = _attack_lines(caplog)
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert secret not in caplog.text

    metadata = _single_threat_event_metadata(mock_agent)
    assert secret not in json.dumps(metadata, default=str)


@pytest.mark.parametrize("surface", _SURFACES)
def test_array_of_objects_under_sensitive_key_nested_leaf_redacted(
    surface: str, caplog: pytest.LogCaptureFixture, mock_agent: MagicMock
) -> None:
    secret = f"ARRVAL-SECRET-{surface}"
    payload = json.dumps({"password": [{"inner": f"{secret} {_XSS}"}]})
    request = _surface_request(surface, payload)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is True
    lines = _attack_lines(caplog)
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert secret not in caplog.text

    metadata = _single_threat_event_metadata(mock_agent)
    assert secret not in json.dumps(metadata, default=str)


@pytest.mark.parametrize("surface", _SURFACES)
def test_array_of_objects_sensitive_key_redacted(
    surface: str, caplog: pytest.LogCaptureFixture, mock_agent: MagicMock
) -> None:
    secret = f"ARRAY-SECRET-{surface}"
    payload = json.dumps([{"password": f"{secret} {_XSS}"}, {"note": "benign"}])
    request = _surface_request(surface, payload)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is True
    lines = _attack_lines(caplog)
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert secret not in caplog.text

    metadata = _single_threat_event_metadata(mock_agent)
    assert secret not in json.dumps(metadata, default=str)


@pytest.mark.parametrize("surface", _SURFACES)
def test_sensitive_value_longer_than_cap_never_partially_leaks(
    surface: str, caplog: pytest.LogCaptureFixture, mock_agent: MagicMock
) -> None:
    padding = "X" * 150
    secret = f"SECRET-LONG-{surface}-{padding} {_XSS}"
    payload = json.dumps({"password": secret})
    request = _surface_request(surface, payload)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is True
    lines = _attack_lines(caplog)
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert f"SECRET-LONG-{surface}" not in caplog.text
    assert padding not in caplog.text

    metadata = _single_threat_event_metadata(mock_agent)
    dumped = json.dumps(metadata, default=str)
    assert f"SECRET-LONG-{surface}" not in dumped
    assert padding not in dumped


@pytest.mark.parametrize("surface", _SURFACES)
def test_json_key_trips_pattern_key_stays_raw_for_non_sensitive_parent(
    surface: str, mock_agent: MagicMock
) -> None:
    key = _XSS
    payload = json.dumps({key: "benign"})
    request = _surface_request(surface, payload)

    result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is True
    assert key in result.trigger_info

    metadata = _single_threat_event_metadata(mock_agent)
    assert key in metadata["context"]


@pytest.mark.parametrize("surface", _SURFACES)
def test_attack_only_in_sensitive_field_outer_line_redacted(
    surface: str, caplog: pytest.LogCaptureFixture, mock_agent: MagicMock
) -> None:
    secret = f"SOLE-ATTACK-SECRET-{surface}"
    payload = json.dumps({"password": f"{secret} {_XSS}", "note": "benign"})
    request = _surface_request(surface, payload)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is True
    lines = _attack_lines(caplog)
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert secret not in caplog.text

    metadata = _single_threat_event_metadata(mock_agent)
    assert secret not in json.dumps(metadata, default=str)


@pytest.mark.parametrize("surface", ["header", "query_param"])
def test_sensitive_parent_blanket_redacts_nested_json(
    surface: str, caplog: pytest.LogCaptureFixture, mock_agent: MagicMock
) -> None:
    secret = f"SENSITIVE-PARENT-SECRET-{surface}"
    payload = json.dumps({"note": _XSS, "harmless_key": secret})

    if surface == "header":
        config = SyncSecurityConfig(log_sensitive_headers={"x-session"})
        request = SyncMockGuardRequest(headers={"X-Session": payload})
    else:
        config = SyncSecurityConfig(log_sensitive_params={"tok"})
        request = SyncMockGuardRequest(query_params={"tok": payload})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    lines = _attack_lines(caplog)
    assert lines, "no detection log line captured"
    assert "[REDACTED]" in lines[0]
    assert _XSS not in caplog.text
    assert secret not in caplog.text

    metadata = _single_threat_event_metadata(mock_agent)
    assert metadata["content_preview"] == "[REDACTED]"
    dumped = json.dumps(metadata, default=str)
    assert secret not in dumped
    assert _XSS not in dumped
