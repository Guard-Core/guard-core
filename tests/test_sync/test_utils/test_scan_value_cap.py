import json
import logging

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.detection_scan import LazyPreview
from guard_core.sync.handlers.suspatterns_handler import (
    DetectionResult,
    SusPatternsManager,
)
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_SQLI_PAYLOAD = "1 OR 1=1 UNION SELECT password FROM users--"


def _query_request(
    params: dict[str, str], client_host: str = "127.0.0.1"
) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(query_params=params, client_host=client_host)


def _header_request(
    headers: dict[str, str], client_host: str = "127.0.0.1"
) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(headers=headers, client_host=client_host)


def _padded_json(payload_key: str | None = None) -> str:
    fields = {f"field{i}": "benign" for i in range(20)}
    if payload_key is not None:
        fields = {payload_key: _SQLI_PAYLOAD, **fields}
    return json.dumps(fields)


def test_payload_within_the_cap_is_still_detected() -> None:
    config = SyncSecurityConfig(detection_max_scan_values=2)
    request = _query_request({"q": _SQLI_PAYLOAD})

    result = detect_penetration_attempt(request, config)

    assert result.is_threat is True


def test_payload_past_the_cap_is_scanned_as_one_block() -> None:
    config = SyncSecurityConfig(detection_max_scan_values=2)
    params = {f"pad{i}": "benign" for i in range(20)}
    params["payload"] = _SQLI_PAYLOAD
    request = _query_request(params)

    result = detect_penetration_attempt(request, config)

    assert result.is_threat is True
    assert result.trigger_info.startswith("Remaining query params")


def test_cap_reached_logs_a_single_warning_naming_the_client_ip(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(detection_max_scan_values=2)
    params = {f"pad{i}": "benign" for i in range(20)}
    params["payload"] = _SQLI_PAYLOAD
    request = _query_request(params, client_host="203.0.113.77")

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        detect_penetration_attempt(request, config)

    assert caplog.text.count("detection_max_scan_values") == 1
    assert "203.0.113.77" in caplog.text


def test_scan_value_budget_resets_between_requests(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(detection_max_scan_values=2)
    params = {f"pad{i}": "benign" for i in range(20)}
    params["payload"] = _SQLI_PAYLOAD
    request = _query_request(params)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        detect_penetration_attempt(request, config)
        detect_penetration_attempt(request, config)

    assert caplog.text.count("detection_max_scan_values") == 2


def test_default_cap_never_trips_on_an_ordinary_request(
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = _query_request({"q": _SQLI_PAYLOAD})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is True
    assert "detection_max_scan_values" not in caplog.text


def test_config_none_still_uses_the_default_cap(
    caplog: pytest.LogCaptureFixture,
) -> None:
    params = {f"pad{i}": "benign" for i in range(600)}
    request = _query_request(params)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request)

    assert result.is_threat is False
    assert "detection_max_scan_values" in caplog.text


def test_json_embedded_in_a_query_param_value_trips_the_cap(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(detection_max_scan_values=2)
    request = _query_request({"q": _padded_json()})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is False
    assert caplog.text.count("detection_max_scan_values") == 1


def test_json_embedded_in_a_header_value_trips_the_cap(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(detection_max_scan_values=2)
    request = _header_request({"X-Custom-Data": _padded_json()})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is False
    assert caplog.text.count("detection_max_scan_values") == 1


def test_json_embedded_payload_placed_before_the_cap_is_still_detected() -> None:
    config = SyncSecurityConfig(detection_max_scan_values=5)
    request = _query_request({"q": _padded_json(payload_key="payload")})

    result = detect_penetration_attempt(request, config)

    assert result.is_threat is True


def test_json_embedded_scan_calls_detect_no_more_than_the_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SyncSecurityConfig(detection_max_scan_values=2)
    request = _query_request({"q": _padded_json()})

    call_count = 0
    original_detect = SusPatternsManager.detect

    def counting_detect(
        self: SusPatternsManager,
        content: str,
        ip_address: str,
        context: str = "unknown",
        correlation_id: str | None = None,
        enabled_categories: set[str] | None = None,
        *,
        content_preview: str | LazyPreview | None = None,
    ) -> DetectionResult:
        nonlocal call_count
        if context.startswith("query_param"):
            call_count += 1
        return original_detect(
            self,
            content,
            ip_address,
            context,
            correlation_id,
            enabled_categories,
            content_preview=content_preview,
        )

    monkeypatch.setattr(SusPatternsManager, "detect", counting_detect)

    detect_penetration_attempt(request, config)

    assert call_count == 2
