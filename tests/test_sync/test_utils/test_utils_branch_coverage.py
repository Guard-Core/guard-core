import json
import logging
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.utils import (
    _build_log_message_for_suspicious,
    _check_blocked_countries,
    _check_embedded_json,
    _extract_request_context,
    _is_trusted_proxy,
    _log_at_level,
    _log_country_check_result,
    detect_penetration_attempt,
)


def test_is_trusted_proxy_cidr_not_matching() -> None:
    assert _is_trusted_proxy("10.0.0.1", ["192.168.0.0/16"]) is False


def test_extract_request_context_missing_client_host() -> None:
    request = MagicMock()
    request.state.client_ip = None
    request.client_host = None
    request.method = "GET"
    request.url_full = "http://test/"
    request.headers = {}
    ctx = _extract_request_context(request, None, None)
    assert ctx["client_ip"] == "unknown"


def test_extract_request_context_uses_resolved_client_ip_from_state() -> None:
    request = MagicMock()
    request.state.client_ip = "203.0.113.7"
    request.client_host = "10.0.0.1"
    request.method = "GET"
    request.url_full = "http://test/"
    request.headers = {}
    ctx = _extract_request_context(request, None, None)
    assert ctx["client_ip"] == "203.0.113.7"


def test_extract_request_context_falls_back_to_client_host_without_state_ip() -> None:
    request = MagicMock()
    request.state.client_ip = None
    request.client_host = "10.0.0.1"
    request.method = "GET"
    request.url_full = "http://test/"
    request.headers = {}
    ctx = _extract_request_context(request, None, None)
    assert ctx["client_ip"] == "10.0.0.1"


def test_build_log_message_for_suspicious_passive_mode_no_trigger() -> None:
    context = {
        "client_ip": "1.2.3.4",
        "method": "GET",
        "url": "http://x/",
        "headers": {},
    }
    details, reason = _build_log_message_for_suspicious(
        context, reason="", passive_mode=True, trigger_info=""
    )
    assert "[PASSIVE MODE]" in details
    assert "Trigger" not in reason


def test_log_at_level_unknown_level_is_noop(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("guard_core.test.log_at_level_unknown")
    with caplog.at_level(logging.DEBUG, logger=logger.name):
        _log_at_level(logger, "NOPE", "test-msg")
    assert not caplog.records


def test_log_country_check_result_unknown_type_is_noop(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.DEBUG, logger="root"):
        _log_country_check_result("1.2.3.4", "US", "not_a_known_type", MagicMock())
    assert not any("1.2.3.4" in r.getMessage() for r in caplog.records)


def test_check_blocked_countries_country_not_blocked() -> None:
    config = MagicMock()
    config.blocked_countries = ["CN"]
    geo_ip = MagicMock()
    with patch(
        "guard_core.sync._utils.access_control.check_ip_country",
        new=MagicMock(return_value=False),
    ) as mock_check:

        def _async_false(*_a: object, **_kw: object) -> bool:
            return False

        mock_check.side_effect = _async_false
        result = _check_blocked_countries("1.2.3.4", config, geo_ip)
    assert result is True


def test_check_blocked_countries_country_blocked() -> None:
    config = MagicMock()
    config.blocked_countries = ["CN"]
    geo_ip = MagicMock()
    with patch(
        "guard_core.sync._utils.access_control.check_ip_country",
        new=MagicMock(return_value=True),
    ) as mock_check:

        def _async_true(*_a: object, **_kw: object) -> bool:
            return True

        mock_check.side_effect = _async_true
        result = _check_blocked_countries("1.2.3.4", config, geo_ip)
    assert result is False


def test_check_blocked_countries_no_rules_skips_lookup() -> None:
    config = MagicMock()
    config.blocked_countries = []
    config.whitelist_countries = []
    geo_ip = MagicMock()
    with patch(
        "guard_core.sync._utils.access_control.check_ip_country",
        new=MagicMock(return_value=True),
    ) as mock_check:

        def _async_true(*_a: object, **_kw: object) -> bool:
            return True

        mock_check.side_effect = _async_true
        result = _check_blocked_countries("1.2.3.4", config, geo_ip)
    assert result is True
    mock_check.assert_not_called()


def test_embedded_json_walker_scans_non_string_and_nested_values() -> None:
    from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

    with patch.object(sus_patterns_handler, "detect") as mock_detect:

        def _async_miss(*_a: object, **_kw: object) -> dict[str, object]:
            return {"is_threat": False, "threats": []}

        mock_detect.side_effect = _async_miss
        result = _check_embedded_json(
            json.dumps({"k1": 123, "k2": None, "k3": ["a"]}),
            "test",
            "1.2.3.4",
            "cid",
            None,
            frozenset(),
            frozenset(),
            False,
        )
    assert result is not None
    assert result[0] is False
    scanned_contents = {call.kwargs["content"] for call in mock_detect.call_args_list}
    assert scanned_contents == {"k1", "k2", "123", "None", "k3", "a"}


def test_embedded_json_key_nested_context_stays_a_known_context() -> None:
    from guard_core.sync.handlers.suspatterns_handler import (
        SusPatternsManager,
        sus_patterns_handler,
    )

    with patch.object(sus_patterns_handler, "detect") as mock_detect:

        def _async_miss(*_a: object, **_kw: object) -> dict[str, object]:
            return {"is_threat": False, "threats": []}

        mock_detect.side_effect = _async_miss
        _check_embedded_json(
            json.dumps({"username": "safe value"}),
            "url_path",
            "1.2.3.4",
            "cid",
            None,
            frozenset(),
            frozenset(),
            False,
        )

    scanned_contexts = {call.kwargs["context"] for call in mock_detect.call_args_list}
    assert scanned_contexts == {
        "url_path:embedded_json:username",
        "url_path:embedded_json",
    }
    normalized = {SusPatternsManager._normalize_context(c) for c in scanned_contexts}
    assert normalized == {"url_path"}
    assert "unknown" not in normalized


def test_detect_penetration_attempt_no_client_host() -> None:
    request = MagicMock()
    request.client_host = None
    request.query_params = {}
    request.url_path = "/"
    request.headers = {}

    def _body() -> bytes:
        return b""

    request.body = _body

    _dpa = detect_penetration_attempt(request)

    detected = _dpa.is_threat
    assert detected is False


def test_detect_penetration_attempt_excluded_header_still_detects_xss() -> None:
    request = MagicMock()
    request.client_host = "1.2.3.4"
    request.query_params = {}
    request.url_path = "/"
    request.headers = {"User-Agent": "<script>alert(1)</script>"}

    def _body() -> bytes:
        return b""

    request.body = _body

    _dpa = detect_penetration_attempt(request)

    detected = _dpa.is_threat
    assert detected is True


def test_detect_penetration_attempt_non_excluded_header_hit() -> None:
    request = MagicMock()
    request.client_host = "1.2.3.4"
    request.query_params = {}
    request.url_path = "/"
    request.headers = {"X-Custom": "<script>alert(1)</script>"}

    def _body() -> bytes:
        return b""

    request.body = _body

    result = detect_penetration_attempt(request)

    assert result.is_threat is True


def test_detect_penetration_attempt_scan_body_disabled_skips_the_body() -> None:
    request = MagicMock()
    request.client_host = "1.2.3.4"
    request.query_params = {}
    request.url_path = "/"
    request.headers = {}
    config = SyncSecurityConfig(detection_scan_body=False)
    body_called = False

    def _body() -> bytes:
        nonlocal body_called
        body_called = True
        return b'{"q": "1 OR 1=1 UNION SELECT password FROM users--"}'

    request.body = _body

    result = detect_penetration_attempt(request, config)

    assert result.is_threat is False
    assert body_called is False
