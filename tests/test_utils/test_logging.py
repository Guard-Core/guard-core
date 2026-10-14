import json
import logging
import os
import time
from collections.abc import Iterator
from typing import Any
from unittest.mock import patch
from urllib.parse import quote, quote_plus

import pytest
from pytest_mock import MockerFixture

from guard_core._utils.logging_utils import _redact_sensitive_json
from guard_core._utils.request_logging import (
    _dispatch_block_hook,
    _redact_sensitive_headers,
    _redact_sensitive_query_params,
    redact_endpoint_for_display,
    redact_header_value_for_display,
)
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.utils import (
    UNKNOWN_CLIENT_IDENTITY,
    detect_penetration_attempt,
    is_ip_allowed,
    is_user_agent_allowed,
    log_activity,
    setup_custom_logging,
)
from tests.conftest import MockGuardRequest


class _RecordingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture(autouse=True)
def _restore_logger_state() -> Iterator[None]:
    root_logger = logging.getLogger()
    guard_logger = logging.getLogger("guard_core")
    original_root_handlers = root_logger.handlers[:]
    original_root_level = root_logger.level
    original_guard_handlers = guard_logger.handlers[:]
    original_guard_level = guard_logger.level
    original_guard_propagate = guard_logger.propagate
    yield
    for handler in guard_logger.handlers[:]:
        if handler not in original_guard_handlers:
            handler.close()
    guard_logger.handlers = original_guard_handlers
    guard_logger.setLevel(original_guard_level)
    guard_logger.propagate = original_guard_propagate
    for handler in root_logger.handlers[:]:
        if handler not in original_root_handlers:
            handler.close()
    root_logger.handlers = original_root_handlers
    root_logger.setLevel(original_root_level)


async def test_is_ip_allowed(
    security_config: SecurityConfig, mocker: MockerFixture
) -> None:
    mocker.patch("guard_core.utils.check_ip_country", return_value=False)

    assert await is_ip_allowed("127.0.0.1", security_config)
    assert not await is_ip_allowed("192.168.1.1", security_config)

    empty_config = SecurityConfig(whitelist=[], blacklist=[])
    assert await is_ip_allowed("127.0.0.1", empty_config)
    assert await is_ip_allowed("192.168.1.1", empty_config)

    whitelist_config = SecurityConfig(whitelist=["127.0.0.1"])
    assert await is_ip_allowed("127.0.0.1", whitelist_config)
    assert not await is_ip_allowed("192.168.1.1", whitelist_config)

    blacklist_config = SecurityConfig(blacklist=["192.168.1.1"])
    assert await is_ip_allowed("127.0.0.1", blacklist_config)
    assert not await is_ip_allowed("192.168.1.1", blacklist_config)


async def test_is_user_agent_allowed(security_config: SecurityConfig) -> None:
    assert await is_user_agent_allowed("goodbot", security_config)
    assert not await is_user_agent_allowed("badbot", security_config)


async def test_custom_logging(security_config: SecurityConfig, tmp_path: Any) -> None:
    log_file = tmp_path / "test_log.log"
    logger = setup_custom_logging(str(log_file))

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"user-agent": "test-agent"},
        client_host="127.0.0.1",
    )

    await log_activity(request, logger)

    with open(log_file) as f:
        log_content = f.read()
        assert "Request from 127.0.0.1: GET https://test/" in log_content


async def test_detected_component_with_lone_surrogate_writes_intact_log_line(
    tmp_path: Any,
) -> None:
    log_file = tmp_path / "audit.log"
    setup_custom_logging(str(log_file))

    body = b"\x88cshutil\nrmtree\n(S'/tmp/x'\ntR."
    request = MockGuardRequest(
        method="POST",
        headers={"content-length": str(len(body))},
        body_content=body,
    )

    result = await detect_penetration_attempt(request, SecurityConfig())
    assert result.is_threat is True

    with open(log_file, encoding="utf-8") as f:
        log_content = f.read()
    assert log_content, "audit log entry was silently dropped"
    assert "Potential attack detected" in log_content
    assert "\\x88" in log_content
    assert "\udc88" not in log_content


async def test_detect_penetration_attempt_attributes_real_client_ip_behind_proxy(
    tmp_path: Any,
) -> None:
    log_file = tmp_path / "audit.log"
    setup_custom_logging(str(log_file))

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Forwarded-For": "203.0.113.7", "user-agent": "test-agent"},
        client_host="10.0.0.1",
        query_params={"q": "<script>alert(1)</script>"},
    )

    config = SecurityConfig(trusted_proxies=["10.0.0.1"], trusted_proxy_depth=1)
    result = await detect_penetration_attempt(request, config)
    assert result.is_threat is True

    with open(log_file, encoding="utf-8") as f:
        log_content = f.read()
    detection_lines = [
        line for line in log_content.splitlines() if "Potential attack detected" in line
    ]
    assert detection_lines, "no detection log line written"
    for line in detection_lines:
        assert "Potential attack detected from 203.0.113.7" in line
        assert "from 10.0.0.1" not in line


async def test_detect_penetration_attempt_falls_back_to_connecting_ip_without_config(
    tmp_path: Any,
) -> None:
    log_file = tmp_path / "audit.log"
    setup_custom_logging(str(log_file))

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"user-agent": "test-agent"},
        client_host="198.51.100.5",
        query_params={"q": "<script>alert(1)</script>"},
    )

    result = await detect_penetration_attempt(request, None)
    assert result.is_threat is True

    with open(log_file, encoding="utf-8") as f:
        log_content = f.read()
    detection_lines = [
        line for line in log_content.splitlines() if "Potential attack detected" in line
    ]
    assert detection_lines, "no detection log line written"
    for line in detection_lines:
        assert "Potential attack detected from 198.51.100.5" in line


async def test_log_request(caplog: pytest.LogCaptureFixture) -> None:
    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"user-agent": "test-agent"},
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.INFO):
        await log_activity(request, logger)

    assert "Request from 127.0.0.1: GET https://test/" in caplog.text
    assert "Headers: {'user-agent': 'test-agent'}" in caplog.text


async def test_log_suspicious_activity(caplog: pytest.LogCaptureFixture) -> None:
    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"user-agent": "test-agent"},
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.WARNING):
        await log_activity(
            request,
            logger,
            log_type="suspicious",
            reason="Suspicious activity detected",
        )

    assert "Suspicious activity detected" in caplog.text
    assert "127.0.0.1" in caplog.text
    assert "GET https://test/" in caplog.text


async def test_log_suspicious_activity_passive_mode(
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"user-agent": "test-agent"},
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.WARNING):
        await log_activity(
            request,
            logger,
            log_type="suspicious",
            reason="Suspicious activity detected",
            passive_mode=True,
            trigger_info="SQL injection attempt",
        )

    assert "[PASSIVE MODE] Penetration attempt detected from" in caplog.text
    assert "127.0.0.1" in caplog.text
    assert "GET https://test/" in caplog.text
    assert "Trigger: SQL injection attempt" in caplog.text


async def test_log_custom_type(caplog: pytest.LogCaptureFixture) -> None:
    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"user-agent": "test-agent"},
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.WARNING):
        await log_activity(
            request, logger, log_type="custom_event", reason="Custom event reason"
        )

    assert "Custom_event from 127.0.0.1: GET https://test/" in caplog.text
    assert "Details: Custom event reason" in caplog.text
    assert "Headers: {'user-agent': 'test-agent'}" in caplog.text


def test_setup_custom_logging_always_attaches_console_and_file_handlers(
    tmp_path: Any,
) -> None:
    log_file = tmp_path / "security.log"
    logger = setup_custom_logging(str(log_file))

    handler_count = sum(
        1
        for h in logger.handlers
        if isinstance(h, logging.FileHandler | logging.StreamHandler)
    )
    assert handler_count == 2


def test_no_duplicate_emission_when_root_is_configured_before_guard(
    capsys: pytest.CaptureFixture[str],
) -> None:
    logging.basicConfig(force=True)
    recorder = _RecordingHandler()
    logging.getLogger().addHandler(recorder)

    logger = setup_custom_logging(None, "json")
    console_handler = logger.handlers[0]
    assert isinstance(console_handler, logging.StreamHandler)

    capsys.readouterr()
    logger.warning("root-first-line")

    assert len(recorder.records) == 1
    assert recorder.records[0].getMessage() == "root-first-line"
    assert console_handler.filter(recorder.records[0]) is False

    captured = capsys.readouterr()
    matching_lines = [
        line for line in captured.err.splitlines() if "root-first-line" in line
    ]
    assert len(matching_lines) == 1
    assert not matching_lines[0].startswith("{")


def test_no_duplicate_emission_when_guard_is_configured_before_root(
    capsys: pytest.CaptureFixture[str],
) -> None:
    logging.getLogger().handlers = []
    logger = setup_custom_logging(None, "json")
    console_handler = logger.handlers[0]
    assert isinstance(console_handler, logging.StreamHandler)

    logging.basicConfig(force=True)
    recorder = _RecordingHandler()
    logging.getLogger().addHandler(recorder)

    capsys.readouterr()
    logger.warning("guard-first-line")

    assert len(recorder.records) == 1
    assert recorder.records[0].getMessage() == "guard-first-line"
    assert console_handler.filter(recorder.records[0]) is False

    captured = capsys.readouterr()
    matching_lines = [
        line for line in captured.err.splitlines() if "guard-first-line" in line
    ]
    assert len(matching_lines) == 1
    assert not matching_lines[0].startswith("{")


@pytest.mark.parametrize(
    ("log_format", "expects_json"),
    [("text", False), ("json", True)],
)
def test_setup_custom_logging_emits_once_via_own_handler_when_root_has_no_handlers(
    capsys: pytest.CaptureFixture[str], log_format: str, expects_json: bool
) -> None:
    logging.getLogger().handlers = []

    logger = setup_custom_logging(None, log_format)
    assert len(logger.handlers) == 1
    assert isinstance(logger.handlers[0], logging.StreamHandler)
    assert logger.level == logging.INFO

    capsys.readouterr()
    logger.warning("solo-guard-line")

    captured = capsys.readouterr()
    matching_lines = [
        line for line in captured.err.splitlines() if "solo-guard-line" in line
    ]
    assert len(matching_lines) == 1
    if expects_json:
        assert matching_lines[0].startswith("{")
    else:
        assert matching_lines[0].startswith("[guard_core]")


@pytest.mark.parametrize(
    "ordering",
    ["root_configured_first", "guard_configured_first", "no_root_handlers"],
)
def test_custom_log_file_receives_the_line_in_every_root_handler_ordering(
    tmp_path: Any, ordering: str
) -> None:
    logging.getLogger().handlers = []
    log_file = tmp_path / "audit.log"

    if ordering == "root_configured_first":
        logging.getLogger().addHandler(logging.NullHandler())
        logger = setup_custom_logging(str(log_file))
    elif ordering == "guard_configured_first":
        logger = setup_custom_logging(str(log_file))
        logging.getLogger().addHandler(logging.NullHandler())
    else:
        logger = setup_custom_logging(str(log_file))

    logger.warning("file-line")

    with open(log_file) as f:
        content = f.read()
    assert "file-line" in content


def test_repeated_setup_does_not_stack_handlers_or_filters() -> None:
    setup_custom_logging(None)
    logger = setup_custom_logging(None)
    handler_count_first_call = len(logger.handlers)
    console_handler = logger.handlers[0]
    assert len(console_handler.filters) == 1
    assert logger.level == logging.INFO

    logger = setup_custom_logging(None)
    assert len(logger.handlers) == handler_count_first_call
    new_console_handler = logger.handlers[0]
    assert len(new_console_handler.filters) == 1
    assert logger.level == logging.INFO


def test_setup_custom_logging_keeps_a_foreign_handler_across_repeated_setup() -> None:
    guard_logger = logging.getLogger("guard_core")
    foreign_handler = _RecordingHandler()
    guard_logger.addHandler(foreign_handler)

    try:
        setup_custom_logging(None)
        logger = setup_custom_logging(None)

        assert foreign_handler in logger.handlers
        own_handlers = [h for h in logger.handlers if h is not foreign_handler]
        assert len(own_handlers) == 1

        logger.warning("still-attached")
        assert len(foreign_handler.records) == 1
        assert foreign_handler.records[0].getMessage() == "still-attached"
    finally:
        guard_logger.removeHandler(foreign_handler)


def test_no_duplicate_logs(caplog: pytest.LogCaptureFixture, tmp_path: Any) -> None:
    log_file = tmp_path / "test_no_duplicates.log"

    guard_logger = setup_custom_logging(str(log_file))

    root_logger = logging.getLogger()
    original_handlers = root_logger.handlers.copy()
    original_level = root_logger.level

    root_handler = logging.StreamHandler()
    root_handler.setFormatter(logging.Formatter("ROOT: %(message)s"))
    root_logger.addHandler(root_handler)
    root_logger.setLevel(logging.INFO)

    try:
        caplog.clear()
        caplog.set_level(logging.INFO)

        test_message = "Test message for duplicate check"
        guard_logger.info(test_message)

        matching_records = [r for r in caplog.records if test_message in r.message]

        assert len(matching_records) > 0, "Message should be logged"

        seen = set()
        for record in matching_records:
            key = (record.name, record.message, record.levelname)
            assert key not in seen, f"Duplicate log found: {key}"
            seen.add(key)

        with open(log_file) as f:
            file_content = f.read()
            assert test_message in file_content
            assert file_content.count(test_message) == 1, (
                "Message should appear once in log file"
            )

    finally:
        root_logger.handlers = original_handlers
        root_logger.setLevel(original_level)


def test_hierarchical_namespace_isolation() -> None:
    guard_logger = logging.getLogger("fastapi_guard")
    guard_handler_logger = logging.getLogger("fastapi_guard.handlers.redis")
    user_logger = logging.getLogger("myapp")

    assert guard_handler_logger.parent == guard_logger
    assert guard_logger.parent == logging.getLogger()
    assert user_logger.parent == logging.getLogger()

    assert guard_logger is not user_logger
    assert guard_handler_logger is not user_logger

    assert guard_logger.name == "fastapi_guard"
    assert guard_handler_logger.name == "fastapi_guard.handlers.redis"
    assert user_logger.name == "myapp"


def test_custom_log_file_configuration(tmp_path: Any) -> None:
    custom_log_path = tmp_path / "my_custom_security.log"
    logger = setup_custom_logging(str(custom_log_path))

    test_message = "Custom log file test"
    logger.info(test_message)

    assert custom_log_path.exists(), "Custom log file should be created"
    with open(custom_log_path) as f:
        content = f.read()
        assert test_message in content

    logger_no_file = setup_custom_logging(None)

    file_handlers = [
        h for h in logger_no_file.handlers if isinstance(h, logging.FileHandler)
    ]
    stream_handlers = [
        h for h in logger_no_file.handlers if isinstance(h, logging.StreamHandler)
    ]

    assert len(file_handlers) == 0, "Should have no file handlers when log_file is None"
    assert len(stream_handlers) >= 1, (
        "Should have at least one stream handler for console"
    )


def test_logger_output_reaches_caplog_with_and_without_log_file(
    caplog: pytest.LogCaptureFixture,
) -> None:
    logger_no_file = setup_custom_logging(None)

    caplog.clear()
    caplog.set_level(logging.INFO)

    test_message = "Console output test - no file"
    logger_no_file.info(test_message)

    assert test_message in caplog.text, "Console output should work without file"

    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tmp_file:
        logger_with_file = setup_custom_logging(tmp_file.name)

        caplog.clear()
        test_message_2 = "Console output test - with file"
        logger_with_file.info(test_message_2)

        assert test_message_2 in caplog.text, "Console output should work with file"

        os.unlink(tmp_file.name)


def test_setup_custom_logging_creates_directory(tmp_path: Any) -> None:
    non_existent_dir = tmp_path / "logs" / "subdirectory" / "deep"
    log_file_path = non_existent_dir / "test.log"

    assert not non_existent_dir.exists(), "Directory should not exist initially"

    logger = setup_custom_logging(str(log_file_path))

    assert non_existent_dir.exists(), "Directory should be created"

    file_handlers = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
    assert len(file_handlers) == 1, "Should have exactly one file handler"

    test_message = "Directory creation test"
    logger.info(test_message)

    assert log_file_path.exists(), "Log file should be created"
    with open(log_file_path) as f:
        content = f.read()
        assert test_message in content


def test_setup_custom_logging_file_handler_exception(
    caplog: pytest.LogCaptureFixture, mocker: MockerFixture
) -> None:
    mocker.patch("os.path.exists", return_value=True)
    mocker.patch(
        "guard_core._utils.logging_utils.logging.FileHandler",
        side_effect=PermissionError("Permission denied: cannot create log file"),
    )

    caplog.clear()
    caplog.set_level(logging.WARNING, logger="fastapi_guard")

    logger = setup_custom_logging("/invalid/path/test.log")

    assert "Failed to create log file /invalid/path/test.log" in caplog.text
    assert "Permission denied" in caplog.text or "cannot create log file" in caplog.text

    assert logger is not None

    assert len(logger.handlers) == 1, "Should have exactly one handler"
    assert isinstance(logger.handlers[0], logging.StreamHandler), (
        "Should have console handler"
    )

    caplog.clear()
    caplog.set_level(logging.INFO, logger="fastapi_guard")
    test_message = "Console still works after file handler failure"
    logger.info(test_message)
    assert test_message in caplog.text


async def test_dispatch_block_hook_ignores_non_suspicious_log_types() -> None:
    calls: list[dict[str, Any]] = []

    def hook(request: GuardRequest, payload: dict[str, Any]) -> None:
        calls.append(payload)

    request = MockGuardRequest(path="/", method="GET", client_host="127.0.0.1")

    await _dispatch_block_hook(
        request, "request", "ip_security", "r", "", False, hook, None, None
    )

    assert calls == []
    assert getattr(request.state, "_guard_block_stash", None) is None


async def test_dispatch_block_hook_stashes_block_dispatch_without_firing() -> None:
    calls: list[dict[str, Any]] = []

    def hook(request: GuardRequest, payload: dict[str, Any]) -> None:
        calls.append(payload)

    request = MockGuardRequest(path="/", method="GET", client_host="127.0.0.1")

    await _dispatch_block_hook(
        request,
        "suspicious",
        "ip_security",
        "blacklisted",
        "IPMatch",
        False,
        hook,
        None,
        None,
    )

    assert calls == []
    assert request.state._guard_block_stash == {
        "reason": "blacklisted",
        "trigger_info": "IPMatch",
    }


async def test_dispatch_block_hook_passive_mode_fires_hook_without_status_code() -> (
    None
):
    calls: list[dict[str, Any]] = []

    def hook(request: GuardRequest, payload: dict[str, Any]) -> None:
        calls.append(payload)

    request = MockGuardRequest(path="/", method="GET", client_host="127.0.0.1")

    await _dispatch_block_hook(
        request,
        "suspicious",
        "ip_security",
        "blacklisted",
        "IPMatch",
        True,
        hook,
        None,
        None,
    )

    assert len(calls) == 1
    assert calls[0]["check_name"] == "ip_security"
    assert calls[0]["reason"] == "blacklisted"
    assert calls[0]["trigger_info"] == "IPMatch"
    assert calls[0]["passive_mode"] is True
    assert calls[0]["status_code"] is None
    assert getattr(request.state, "_guard_block_stash", None) is None


async def test_log_activity_passive_mode_fires_on_block_hook(
    caplog: pytest.LogCaptureFixture,
) -> None:
    calls: list[dict[str, Any]] = []

    def hook(request: GuardRequest, payload: dict[str, Any]) -> None:
        calls.append(payload)

    request = MockGuardRequest(
        path="/", method="POST", headers={"user-agent": "t"}, client_host="127.0.0.1"
    )

    with caplog.at_level(logging.WARNING):
        await log_activity(
            request,
            logging.getLogger(__name__),
            log_type="suspicious",
            reason="blacklisted",
            passive_mode=True,
            trigger_info="IPMatch",
            check_name="suspicious_activity",
            on_block=hook,
        )

    assert len(calls) == 1
    assert calls[0]["check_name"] == "suspicious_activity"
    assert calls[0]["passive_mode"] is True


async def test_log_level(caplog: pytest.LogCaptureFixture) -> None:
    from typing import Literal

    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"user-agent": "test-agent"},
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)

    LOG_LEVELS: list[
        Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] | None
    ] = [
        "INFO",
        "DEBUG",
        "WARNING",
        "ERROR",
        "CRITICAL",
        None,
    ]

    for level in LOG_LEVELS:
        caplog.clear()

        with caplog.at_level(logging.DEBUG):
            await log_activity(request, logger, level=level)

        if level is not None:
            assert len(caplog.records) == 1
            assert caplog.records[0].levelname == level
        else:
            assert len(caplog.records) == 0


async def test_behavior_tracker_passive_mode_logging(
    security_config: SecurityConfig,
) -> None:
    from typing import Literal

    from guard_core.handlers.behavior_handler import BehaviorRule, BehaviorTracker

    security_config.passive_mode = True
    tracker = BehaviorTracker(security_config)

    test_cases: list[tuple[Literal["ban", "log", "throttle", "alert"], str, str]] = [
        (
            "ban",
            "warning",
            "[PASSIVE MODE] Would ban IP 192.168.1.1 for behavioral "
            "violation: Test details",
        ),
        (
            "log",
            "warning",
            "[PASSIVE MODE] Behavioral anomaly detected: Test details",
        ),
        (
            "throttle",
            "warning",
            "[PASSIVE MODE] Would throttle IP 192.168.1.1: Test details",
        ),
        (
            "alert",
            "critical",
            "[PASSIVE MODE] ALERT - Behavioral anomaly: Test details",
        ),
    ]

    for action, log_level, expected_message in test_cases:
        rule = BehaviorRule(
            rule_type="usage",
            threshold=5,
            action=action,
        )

        with patch.object(tracker.logger, log_level) as mock_logger:
            await tracker.apply_action(
                rule=rule,
                client_ip="192.168.1.1",
                endpoint_id="/api/test",
                details="Test details",
            )

            mock_logger.assert_called_once_with(expected_message)


_SENSITIVE_HEADERS_REQUEST = {
    "Authorization": "Bearer tok123",
    "Cookie": "sid=abc",
    "X-API-Key": "sekrit",
    "Proxy-Authorization": "Basic zzz",
    "user-agent": "test-agent",
}


@pytest.mark.parametrize(
    "log_kwargs",
    [
        pytest.param({"level": "INFO"}, id="request_at_info"),
        pytest.param(
            {"log_type": "suspicious", "reason": "Suspicious activity detected"},
            id="suspicious_active",
        ),
        pytest.param(
            {
                "log_type": "suspicious",
                "reason": "Suspicious activity detected",
                "passive_mode": True,
                "trigger_info": "SQL injection attempt",
            },
            id="suspicious_passive_with_trigger_info",
        ),
        pytest.param(
            {"log_type": "blocked", "reason": "Blocked by policy"},
            id="generic_blocked",
        ),
    ],
)
async def test_log_activity_redacts_sensitive_headers_across_log_types(
    caplog: pytest.LogCaptureFixture, log_kwargs: dict[str, Any]
) -> None:
    request = MockGuardRequest(
        path="/",
        method="GET",
        headers=dict(_SENSITIVE_HEADERS_REQUEST),
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.DEBUG):
        await log_activity(request, logger, **log_kwargs)

    assert caplog.text.count("[REDACTED]") == 4
    assert "test-agent" in caplog.text
    assert "tok123" not in caplog.text
    assert "sid=abc" not in caplog.text
    assert "sekrit" not in caplog.text
    assert "zzz" not in caplog.text


async def test_log_activity_preserves_original_header_key_casing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-API-Key": "sekrit"},
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.WARNING):
        await log_activity(request, logger)

    assert "'X-API-Key': '[REDACTED]'" in caplog.text


async def test_log_activity_custom_sensitive_headers_redact_case_insensitively(
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={
            "x-internal-token": "internal-secret",
            "Authorization": "Bearer tok123",
        },
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.WARNING):
        await log_activity(
            request, logger, sensitive_headers=frozenset({"X-Internal-Token"})
        )

    assert "internal-secret" not in caplog.text
    assert "tok123" not in caplog.text
    assert caplog.text.count("[REDACTED]") == 2


async def test_log_activity_sensitive_headers_none_still_redacts_defaults(
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"Authorization": "Bearer tok123"},
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.WARNING):
        await log_activity(request, logger, sensitive_headers=None)

    assert "tok123" not in caplog.text
    assert "[REDACTED]" in caplog.text


def test_redact_sensitive_headers_empty_input_returns_empty_dict() -> None:
    assert _redact_sensitive_headers({}, None) == {}


def test_redact_sensitive_headers_with_no_sensitive_names_unchanged() -> None:
    headers = {"user-agent": "test-agent", "accept": "*/*"}
    assert _redact_sensitive_headers(headers, None) == headers


def test_redact_sensitive_headers_none_uses_default_set_only() -> None:
    headers = {"Authorization": "secret", "X-Internal-Token": "keepme"}
    result = _redact_sensitive_headers(headers, None)
    assert result == {"Authorization": "[REDACTED]", "X-Internal-Token": "keepme"}


async def test_log_activity_falls_back_to_unknown_client_identity_without_ip(
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"user-agent": "test-agent"},
        client_host=None,
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.INFO):
        await log_activity(request, logger)

    assert UNKNOWN_CLIENT_IDENTITY in caplog.text


async def test_log_suspicious_activity_passive_mode_without_trigger_info_omits_trigger(
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"user-agent": "test-agent"},
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.WARNING):
        await log_activity(
            request,
            logger,
            log_type="suspicious",
            reason="Suspicious activity detected",
            passive_mode=True,
            trigger_info="",
        )

    assert "[PASSIVE MODE] Suspicious activity detected from" in caplog.text
    assert "Penetration attempt" not in caplog.text
    assert "Reason: Suspicious activity detected" in caplog.text
    assert "Trigger:" not in caplog.text


def test_redact_sensitive_headers_non_empty_frozenset_extends_default_set() -> None:
    headers = {"Authorization": "secret", "X-Internal-Token": "keepme"}
    result = _redact_sensitive_headers(headers, frozenset({"x-internal-token"}))
    assert result == {
        "Authorization": "[REDACTED]",
        "X-Internal-Token": "[REDACTED]",
    }


def test_redact_sensitive_headers_embedded_json_sensitive_field_redacted() -> None:
    headers = {"X-Custom": json.dumps({"password": "S1", "note": "n"})}
    result = _redact_sensitive_headers(headers, None)
    assert result == {"X-Custom": '{"password":"[REDACTED]","note":"n"}'}


def test_redact_sensitive_headers_embedded_json_without_sensitive_keys_unchanged() -> (
    None
):
    value = json.dumps({"note": "n", "other": "x"})
    headers = {"X-Custom": value}
    assert _redact_sensitive_headers(headers, None) == headers


def test_redact_sensitive_headers_non_json_value_unchanged() -> None:
    headers = {"X-Custom": "not-json {still not json"}
    assert _redact_sensitive_headers(headers, None) == headers


def test_redact_sensitive_headers_custom_sensitive_body_fields_extends_default() -> (
    None
):
    headers = {"X-Custom": json.dumps({"custom_secret": "S1", "note": "n"})}
    result = _redact_sensitive_headers(
        headers, None, sensitive_body_fields=frozenset({"custom_secret"})
    )
    assert result == {"X-Custom": '{"custom_secret":"[REDACTED]","note":"n"}'}


def test_redact_sensitive_headers_referer_query_token_redacted() -> None:
    headers = {"Referer": "https://evil.example/path?token=SECRET&x=1"}
    result = _redact_sensitive_headers(headers, None)
    assert result == {"Referer": "https://evil.example/path?token=[REDACTED]&x=1"}


def test_redact_sensitive_headers_ampersand_pair_in_non_sensitive_header_redacted() -> (
    None
):
    headers = {"X-Custom": "a=1&token=SECRET"}
    result = _redact_sensitive_headers(headers, None)
    assert result == {"X-Custom": "a=1&token=[REDACTED]"}


def test_redact_sensitive_headers_pair_after_space_redacted() -> None:
    headers = {"User-Agent": "Mozilla/5.0 password=SECRET"}
    result = _redact_sensitive_headers(headers, None)
    assert result == {"User-Agent": "Mozilla/5.0 password=[REDACTED]"}


def test_redact_sensitive_headers_xml_element_redacted() -> None:
    headers = {"X-Custom": "<user>bob</user><password>SECRET</password>"}
    result = _redact_sensitive_headers(headers, None)
    assert result == {"X-Custom": "<user>bob</user><password>[REDACTED]</password>"}


def test_redact_sensitive_headers_benign_user_agent_byte_identical() -> None:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    assert _redact_sensitive_headers(headers, None) == headers


def test_redact_sensitive_headers_custom_sensitive_params_redacts_pair_value() -> None:
    headers = {"X-Custom": "a=1&custom-param=SECRET"}
    result = _redact_sensitive_headers(
        headers, None, sensitive_params=frozenset({"custom-param"})
    )
    assert result == {"X-Custom": "a=1&custom-param=[REDACTED]"}


async def test_log_activity_referer_header_query_token_redacted_in_headers_dump(
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"Referer": "https://evil.example/path?token=SECRET&x=1"},
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.INFO):
        await log_activity(request, logger, level="INFO")

    assert "token=[REDACTED]" in caplog.text
    assert "SECRET" not in caplog.text


async def test_log_activity_custom_header_ampersand_pair_redacted_in_headers_dump(
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Custom": "a=1&token=SECRET"},
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.INFO):
        await log_activity(request, logger, level="INFO")

    assert "token=[REDACTED]" in caplog.text
    assert "SECRET" not in caplog.text


async def test_log_activity_user_agent_pair_after_space_redacted_in_headers_dump(
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"User-Agent": "Mozilla/5.0 password=SECRET"},
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.INFO):
        await log_activity(request, logger, level="INFO")

    assert "password=[REDACTED]" in caplog.text
    assert "SECRET" not in caplog.text


async def test_log_activity_xml_header_value_redacted_in_headers_dump(
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Custom": "<user>bob</user><password>SECRET</password>"},
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.INFO):
        await log_activity(request, logger, level="INFO")

    assert "<password>[REDACTED]</password>" in caplog.text
    assert "<user>bob</user>" in caplog.text
    assert "SECRET" not in caplog.text


_SENSITIVE_QUERY_REQUEST_PATH = "/api?token=SECRET-Q&q=hello&Api_Key=SECRET-K"


@pytest.mark.parametrize(
    "log_kwargs",
    [
        pytest.param({"level": "INFO"}, id="request_at_info"),
        pytest.param(
            {"log_type": "suspicious", "reason": "Suspicious activity detected"},
            id="suspicious_active",
        ),
        pytest.param(
            {
                "log_type": "suspicious",
                "reason": "Suspicious activity detected",
                "passive_mode": True,
                "trigger_info": "SQL injection attempt",
            },
            id="suspicious_passive_with_trigger_info",
        ),
        pytest.param(
            {"log_type": "blocked", "reason": "Blocked by policy"},
            id="generic_blocked",
        ),
    ],
)
async def test_log_activity_redacts_sensitive_query_params_across_log_types(
    caplog: pytest.LogCaptureFixture, log_kwargs: dict[str, Any]
) -> None:
    request = MockGuardRequest(
        path=_SENSITIVE_QUERY_REQUEST_PATH,
        method="GET",
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.DEBUG):
        await log_activity(request, logger, **log_kwargs)

    assert "token=[REDACTED]" in caplog.text
    assert "Api_Key=[REDACTED]" in caplog.text
    assert "q=hello" in caplog.text
    assert "SECRET-Q" not in caplog.text
    assert "SECRET-K" not in caplog.text


@pytest.mark.parametrize(
    "log_kwargs",
    [
        pytest.param({"level": "INFO"}, id="request_at_info"),
        pytest.param(
            {"log_type": "suspicious", "reason": "Suspicious activity detected"},
            id="suspicious_active",
        ),
        pytest.param(
            {
                "log_type": "suspicious",
                "reason": "Suspicious activity detected",
                "passive_mode": True,
                "trigger_info": "SQL injection attempt",
            },
            id="suspicious_passive_with_trigger_info",
        ),
        pytest.param(
            {"log_type": "blocked", "reason": "Blocked by policy"},
            id="generic_blocked",
        ),
    ],
)
async def test_log_activity_redacts_json_field_in_non_sensitive_header_and_query(
    caplog: pytest.LogCaptureFixture, log_kwargs: dict[str, Any]
) -> None:
    query_value = quote_plus(json.dumps({"password": "S2", "note": "n"}))
    request = MockGuardRequest(
        path=f"/api?data={query_value}",
        method="GET",
        headers={"X-Custom": json.dumps({"password": "S1", "note": "n"})},
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.DEBUG):
        await log_activity(request, logger, **log_kwargs)

    assert '{"password":"[REDACTED]","note":"n"}' in caplog.text
    expected_query_value = quote_plus(
        json.dumps({"password": "[REDACTED]", "note": "n"}, separators=(",", ":"))
    )
    assert f"data={expected_query_value}" in caplog.text
    assert "S1" not in caplog.text
    assert "S2" not in caplog.text


async def test_log_activity_non_json_header_and_json_without_sensitive_keys_untouched(
    caplog: pytest.LogCaptureFixture,
) -> None:
    query_value = quote_plus(json.dumps({"note": "n"}))
    request = MockGuardRequest(
        path=f"/api?data={query_value}",
        method="GET",
        headers={
            "X-Plain": "plain-value",
            "X-Json": json.dumps({"note": "n"}),
        },
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.WARNING):
        await log_activity(request, logger)

    assert "'X-Plain': 'plain-value'" in caplog.text
    assert f"'X-Json': '{json.dumps({'note': 'n'})}'" in caplog.text
    assert f"data={query_value}" in caplog.text
    assert "[REDACTED]" not in caplog.text


async def test_log_activity_custom_sensitive_body_fields_redacts_header_json_field(
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Custom": json.dumps({"custom_secret": "S1", "note": "n"})},
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.WARNING):
        await log_activity(
            request,
            logger,
            sensitive_body_fields=frozenset({"custom_secret"}),
        )

    assert '{"custom_secret":"[REDACTED]","note":"n"}' in caplog.text
    assert "S1" not in caplog.text


async def test_log_activity_custom_sensitive_params_redact_case_insensitively(
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = MockGuardRequest(
        path="/api?sig=SECRET-SIG&q=hello",
        method="GET",
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.WARNING):
        await log_activity(request, logger, sensitive_params=frozenset({"sig"}))

    assert "sig=[REDACTED]" in caplog.text
    assert "SECRET-SIG" not in caplog.text
    assert "q=hello" in caplog.text


async def test_log_activity_sensitive_params_none_still_redacts_defaults(
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = MockGuardRequest(
        path="/api?token=SECRET-TOK",
        method="GET",
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.WARNING):
        await log_activity(request, logger, sensitive_params=None)

    assert "SECRET-TOK" not in caplog.text
    assert "token=[REDACTED]" in caplog.text


def test_redact_sensitive_query_params_no_query_returns_url_unchanged() -> None:
    url = "https://test/api"
    assert _redact_sensitive_query_params(url, None) == url


def test_redact_sensitive_query_params_sensitive_pair_with_value_redacted() -> None:
    result = _redact_sensitive_query_params("https://test/api?token=abc123", None)
    assert result == "https://test/api?token=[REDACTED]"


def test_redact_sensitive_query_params_sensitive_name_without_equals_left_as_is() -> (
    None
):
    result = _redact_sensitive_query_params("https://test/api?token&q=1", None)
    assert result == "https://test/api?token&q=1"


def test_redact_sensitive_query_params_percent_encoded_name_keeps_spelling() -> None:
    result = _redact_sensitive_query_params("https://test/api?api%5Fkey=abc", None)
    assert result == "https://test/api?api%5Fkey=[REDACTED]"


def test_redact_sensitive_query_params_plus_encoded_name_redacted() -> None:
    result = _redact_sensitive_query_params(
        "https://test/api?api+key=abc", frozenset({"api key"})
    )
    assert result == "https://test/api?api+key=[REDACTED]"


def test_redact_sensitive_query_params_blank_value_redacted() -> None:
    result = _redact_sensitive_query_params("https://test/api?token=", None)
    assert result == "https://test/api?token=[REDACTED]"


def test_redact_sensitive_query_params_repeated_names_each_redacted() -> None:
    result = _redact_sensitive_query_params("https://test/api?token=a&token=b", None)
    assert result == "https://test/api?token=[REDACTED]&token=[REDACTED]"


def test_redact_sensitive_query_params_fragment_and_path_preserved() -> None:
    result = _redact_sensitive_query_params(
        "https://test/api/path?token=abc#section", None
    )
    assert result == "https://test/api/path?token=[REDACTED]#section"


def test_redact_sensitive_query_params_unrelated_encoding_untouched() -> None:
    result = _redact_sensitive_query_params("https://test/api?q=a%20b&token=x", None)
    assert result == "https://test/api?q=a%20b&token=[REDACTED]"


def test_redact_sensitive_query_params_uppercase_name_redacted() -> None:
    result = _redact_sensitive_query_params("https://test/api?TOKEN=abc", None)
    assert result == "https://test/api?TOKEN=[REDACTED]"


def test_redact_sensitive_query_params_custom_set_extends_default() -> None:
    result = _redact_sensitive_query_params(
        "https://test/api?sig=abc&token=def", frozenset({"sig"})
    )
    assert result == "https://test/api?sig=[REDACTED]&token=[REDACTED]"


def test_redact_sensitive_query_params_semicolon_separator_redacted() -> None:
    result = _redact_sensitive_query_params(
        "https://test/api?foo=bar;token=SECRET", None
    )
    assert result == "https://test/api?foo=bar;token=[REDACTED]"


def test_redact_sensitive_query_params_mixed_separators_redact_both() -> None:
    result = _redact_sensitive_query_params(
        "https://test/api?a=1;token=S&api_key=K;b=2", None
    )
    assert result == "https://test/api?a=1;token=[REDACTED]&api_key=[REDACTED];b=2"


def test_redact_sensitive_query_params_lone_semicolon_preserved() -> None:
    result = _redact_sensitive_query_params("https://test/api?;", None)
    assert result == "https://test/api?;"


def test_redact_sensitive_query_params_trailing_semicolon_preserved() -> None:
    result = _redact_sensitive_query_params("https://test/api?a=1;", None)
    assert result == "https://test/api?a=1;"


def test_redact_sensitive_query_params_fragment_pair_redacted() -> None:
    result = _redact_sensitive_query_params("https://test/api#token=SECRET", None)
    assert result == "https://test/api#token=[REDACTED]"


def test_redact_sensitive_query_params_fragment_without_equals_untouched() -> None:
    url = "https://test/api#section"
    assert _redact_sensitive_query_params(url, None) == url


def test_redact_sensitive_query_params_fragment_route_with_query_redacted() -> None:
    result = _redact_sensitive_query_params(
        "https://test/api#/route?token=SECRET&x=1", None
    )
    assert result == "https://test/api#/route?token=[REDACTED]&x=1"


def test_redact_sensitive_query_params_fragment_route_without_query_unchanged() -> None:
    url = "https://test/api#/route"
    assert _redact_sensitive_query_params(url, None) == url


def test_redact_sensitive_query_params_fragment_pair_then_question_mark_redacted() -> (
    None
):
    result = _redact_sensitive_query_params("https://test/api#a=1?token=S", None)
    assert result == "https://test/api#a=1?token=[REDACTED]"


def test_redact_sensitive_query_params_userinfo_password_redacted() -> None:
    result = _redact_sensitive_query_params("https://user:PASS@host/p?x=1", None)
    assert result == "https://user:[REDACTED]@host/p?x=1"


def test_redact_sensitive_query_params_userinfo_without_password_unchanged() -> None:
    url = "https://user@host/"
    assert _redact_sensitive_query_params(url, None) == url


def test_redact_sensitive_query_params_ipv6_host_with_port_and_userinfo() -> None:
    result = _redact_sensitive_query_params(
        "https://user:PASS@[2001:db8::1]:8443/p?x=1#token=SECRET", None
    )
    assert result == (
        "https://user:[REDACTED]@[2001:db8::1]:8443/p?x=1#token=[REDACTED]"
    )


def test_redact_sensitive_query_params_fragment_route_then_two_question_marks() -> None:
    result = _redact_sensitive_query_params(
        "https://test/api#/a?b=1?token=SECRET", None
    )
    assert result == "https://test/api#/a?b=1?token=[REDACTED]"


def test_redact_sensitive_query_params_fragment_pair_then_question_mark() -> None:
    result = _redact_sensitive_query_params("https://test/api#token=SECRET?x=1", None)
    assert result == "https://test/api#token=[REDACTED]?x=1"


def test_redact_sensitive_query_params_fragment_starting_with_question_mark() -> None:
    result = _redact_sensitive_query_params("https://test/api#?token=SECRET", None)
    assert result == "https://test/api#?token=[REDACTED]"


def test_redact_sensitive_query_params_fragment_mixed_separators_redacted() -> None:
    result = _redact_sensitive_query_params(
        "https://test/api#/route?x=1&token=SECRET;y=2", None
    )
    assert result == "https://test/api#/route?x=1&token=[REDACTED];y=2"


def test_redact_sensitive_query_params_bare_hash_unchanged() -> None:
    url = "https://test/api#"
    assert _redact_sensitive_query_params(url, None) == url


def test_redact_sensitive_query_params_lone_question_mark_fragment_unchanged() -> None:
    url = "https://test/api#?"
    assert _redact_sensitive_query_params(url, None) == url


def test_redact_sensitive_query_params_fragment_route_only_unchanged() -> None:
    url = "https://test/api#/route"
    assert _redact_sensitive_query_params(url, None) == url


def test_redact_sensitive_query_params_fragment_pair_no_question_mark_redacted() -> (
    None
):
    result = _redact_sensitive_query_params("https://test/api#token=SECRET", None)
    assert result == "https://test/api#token=[REDACTED]"


def test_redact_sensitive_query_params_embedded_json_sensitive_field_redacted() -> None:
    value = quote_plus(json.dumps({"password": "S2", "note": "n"}))
    result = _redact_sensitive_query_params(f"https://test/api?data={value}", None)
    expected_value = quote_plus(
        json.dumps({"password": "[REDACTED]", "note": "n"}, separators=(",", ":"))
    )
    assert result == f"https://test/api?data={expected_value}"


def test_redact_sensitive_query_params_json_value_no_sensitive_key_unchanged() -> None:
    value = quote_plus(json.dumps({"note": "n"}))
    url = f"https://test/api?data={value}"
    assert _redact_sensitive_query_params(url, None) == url


def test_redact_sensitive_query_params_custom_body_fields_extend_default() -> None:
    value = quote_plus(json.dumps({"custom_secret": "S2"}))
    result = _redact_sensitive_query_params(
        f"https://test/api?data={value}",
        None,
        sensitive_body_fields=frozenset({"custom_secret"}),
    )
    expected_value = quote_plus(
        json.dumps({"custom_secret": "[REDACTED]"}, separators=(",", ":"))
    )
    assert result == f"https://test/api?data={expected_value}"


def test_redact_sensitive_query_params_percent_encoded_eq_sensitive_redacted() -> None:
    result = _redact_sensitive_query_params("https://test/api?token%3DS", None)
    assert result == "https://test/api?[REDACTED]"


def test_redact_sensitive_query_params_percent_encoded_eq_non_sensitive_kept() -> None:
    url = "https://test/api?a%3D1"
    assert _redact_sensitive_query_params(url, None) == url


def test_redact_sensitive_query_params_fragment_percent_encoded_equals_redacted() -> (
    None
):
    result = _redact_sensitive_query_params("https://test/api#token%3DS", None)
    assert result == "https://test/api#[REDACTED]"


def test_redact_sensitive_query_params_percent_encoded_no_equals_left_as_is() -> None:
    url = "https://test/api?token%20name"
    assert _redact_sensitive_query_params(url, None) == url


def test_redact_sensitive_query_params_percent_encoded_path_segment_redacted() -> None:
    result = _redact_sensitive_query_params(
        "https://test/api/%7B%22password%22%3A%22S%22%7D/x", None
    )
    assert result == "https://test/api/%7B%22password%22%3A%22%5BREDACTED%5D%22%7D/x"


async def test_log_activity_redacts_sensitive_json_in_unencoded_url_path(
    caplog: pytest.LogCaptureFixture,
) -> None:
    request = MockGuardRequest(
        path='/api/{"password": "PATHSECRET777"}',
        method="GET",
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.INFO):
        await log_activity(request, logger, level="INFO")

    assert "PATHSECRET777" not in caplog.text
    assert "REDACTED" in caplog.text


def test_redact_sensitive_query_params_path_json_no_sensitive_key_unchanged() -> None:
    url = 'https://test/api/{"note":"n"}/x'
    assert _redact_sensitive_query_params(url, None) == url


def test_redact_sensitive_query_params_path_non_json_segments_untouched() -> None:
    url = "https://test/api/users/42"
    assert _redact_sensitive_query_params(url, None) == url


def test_redact_sensitive_query_params_root_path_unchanged() -> None:
    url = "https://test/"
    assert _redact_sensitive_query_params(url, None) == url


def test_redact_sensitive_query_params_path_and_query_both_redacted() -> None:
    segment = quote(json.dumps({"password": "PS"}), safe="")
    url = f"https://test/api/{segment}?token=QS"

    result = _redact_sensitive_query_params(url, None)

    assert "PS" not in result
    assert "QS" not in result
    assert result.count("REDACTED") == 2


def test_redact_sensitive_query_params_smuggled_amp_pair_redacted() -> None:
    result = _redact_sensitive_query_params("https://test/api?a%3D1%26token%3DS", None)
    assert result == "https://test/api?[REDACTED]"


def test_redact_sensitive_query_params_smuggled_semicolon_pair_redacted() -> None:
    result = _redact_sensitive_query_params("https://test/api?token%3DS%3Bb%3D2", None)
    assert result == "https://test/api?[REDACTED]"


def test_redact_sensitive_query_params_smuggled_pair_not_sensitive_unchanged() -> None:
    url = "https://test/api?a%3D1%26b%3D2"
    assert _redact_sensitive_query_params(url, None) == url


def test_redact_sensitive_query_params_fragment_smuggled_pair_redacted() -> None:
    result = _redact_sensitive_query_params("https://test/api#a%3D1%26token%3DS", None)
    assert result == "https://test/api#[REDACTED]"


def test_redact_sensitive_query_params_double_encoded_smuggled_pair_redacted() -> None:
    result = _redact_sensitive_query_params(
        "https://test/api?a%3D1%2526token%3DS", None
    )
    assert result == "https://test/api?[REDACTED]"


def _quote_plus_n(text: str, times: int) -> str:
    encoded = text
    for _ in range(times):
        encoded = quote_plus(encoded)
    return encoded


def test_redact_sensitive_query_params_single_encoded_json_value_redacted() -> None:
    value = _quote_plus_n(json.dumps({"password": "S1"}), 1)
    result = _redact_sensitive_query_params(f"https://test/api?data={value}", None)
    assert "S1" not in result
    assert "REDACTED" in result


def test_redact_sensitive_query_params_double_encoded_json_value_redacted() -> None:
    value = _quote_plus_n(json.dumps({"password": "S2"}), 2)
    result = _redact_sensitive_query_params(f"https://test/api?data={value}", None)
    assert "S2" not in result
    assert "REDACTED" in result


def test_redact_sensitive_query_params_triple_encoded_json_value_redacted() -> None:
    value = _quote_plus_n(json.dumps({"password": "S3"}), 3)
    result = _redact_sensitive_query_params(f"https://test/api?data={value}", None)
    assert "S3" not in result
    assert "REDACTED" in result


def test_redact_sensitive_query_params_quadruple_encoded_json_value_stays_raw() -> None:
    value = _quote_plus_n(json.dumps({"password": "S4"}), 4)
    url = f"https://test/api?data={value}"
    assert _redact_sensitive_query_params(url, None) == url


def test_redact_sensitive_query_params_non_json_value_stays_byte_identical() -> None:
    value = _quote_plus_n("not-json-at-all", 3)
    url = f"https://test/api?data={value}"
    assert _redact_sensitive_query_params(url, None) == url


def test_redact_sensitive_headers_json_scalar_value_unchanged() -> None:
    headers = {"X-Custom": "42"}
    assert _redact_sensitive_headers(headers, None) == headers


def test_redact_sensitive_query_params_matrix_param_after_segment_redacted() -> None:
    result = _redact_sensitive_query_params("https://test/api;token=S/x", None)
    assert result == "https://test/api;token=[REDACTED]/x"


def test_redact_sensitive_query_params_multiple_matrix_params_each_handled() -> None:
    result = _redact_sensitive_query_params("https://test/a;b=1;token=S", None)
    assert result == "https://test/a;b=1;token=[REDACTED]"


def test_redact_sensitive_query_params_matrix_param_without_equals_unchanged() -> None:
    url = "https://test/a;token"
    assert _redact_sensitive_query_params(url, None) == url


def test_redact_sensitive_query_params_json_segment_with_matrix_param_redacted() -> (
    None
):
    segment = json.dumps({"note": "n"}, separators=(",", ":"))
    url = f"https://test/api/{segment};token=S"
    result = _redact_sensitive_query_params(url, None)
    assert result == f"https://test/api/{segment};token=[REDACTED]"


def test_redact_sensitive_query_params_path_segment_keeps_plus_literal() -> None:
    segment = json.dumps({"a": "x+y", "password": "PS"}, separators=(",", ":"))
    url = f"https://test/api/{segment}"
    result = _redact_sensitive_query_params(url, None)
    assert "PS" not in result
    assert "x%2By" in result


def test_redact_sensitive_query_params_query_value_space_round_trips_through_plus() -> (
    None
):
    payload = json.dumps({"a": "x y", "password": "PS"}, separators=(",", ":"))
    url = f"https://test/api?data={quote_plus(payload)}"
    result = _redact_sensitive_query_params(url, None)
    expected_payload = json.dumps(
        {"a": "x y", "password": "[REDACTED]"}, separators=(",", ":")
    )
    assert result == f"https://test/api?data={quote_plus(expected_payload)}"


def test_redact_sensitive_json_max_depth_one_redacts_entire_value() -> None:
    assert _redact_sensitive_json({"a": 1}, frozenset(), frozenset(), 1) == "[REDACTED]"


def test_redact_sensitive_json_container_at_cap_depth_collapses_to_redacted() -> None:
    value = {"a": {"b": {"c": 1}}}
    assert _redact_sensitive_json(value, frozenset(), frozenset(), 2) == {
        "a": "[REDACTED]"
    }


def test_redact_sensitive_json_container_below_cap_depth_expands_normally() -> None:
    value = {"a": {"b": 1}}
    assert _redact_sensitive_json(value, frozenset(), frozenset(), 3) == {"a": {"b": 1}}


def test_redact_sensitive_json_list_beyond_cap_collapses_to_redacted() -> None:
    result = _redact_sensitive_json([1, [2, 3]], frozenset(), frozenset(), 2)
    assert result == [1, "[REDACTED]"]


def test_redact_sensitive_json_sensitive_key_inside_list_item_redacted() -> None:
    value = {"items": [{"password": "S"}]}
    result = _redact_sensitive_json(value, frozenset(), frozenset({"password"}), 10)
    assert result == {"items": [{"password": "[REDACTED]"}]}


def test_redact_sensitive_json_scalar_value_returned_unchanged() -> None:
    assert _redact_sensitive_json("plain", frozenset(), frozenset(), 10) == "plain"
    assert _redact_sensitive_json(42, frozenset(), frozenset(), 10) == 42


def test_redact_sensitive_json_string_leaf_non_json_shaped_value_unchanged() -> None:
    result = _redact_sensitive_json(
        {"note": "plain text"}, frozenset({"password"}), frozenset(), 10
    )
    assert result == {"note": "plain text"}


def test_redact_sensitive_json_string_leaf_invalid_nested_json_falls_back() -> None:
    result = _redact_sensitive_json(
        {"note": "{not valid json"}, frozenset({"password"}), frozenset(), 10
    )
    assert result == {"note": "{not valid json"}


def test_redact_sensitive_json_string_leaf_nested_json_sensitive_key_redacted() -> None:
    result = _redact_sensitive_json(
        {"note": '{"password": "SECRET"}'}, frozenset(), frozenset({"password"}), 10
    )
    assert result == {"note": '{"password":"[REDACTED]"}'}


def test_redact_sensitive_json_string_leaf_nested_json_no_sensitive_key_unchanged() -> (
    None
):
    text = '{"note": "plain"}'
    result = _redact_sensitive_json(
        {"note": text}, frozenset({"password"}), frozenset(), 10
    )
    assert result == {"note": text}


def test_redact_sensitive_json_string_leaf_percent_encoded_nested_json_redacted() -> (
    None
):
    value = "%7B%22password%22%3A%22SECRET%22%7D"
    result = _redact_sensitive_json(
        {"note": value}, frozenset(), frozenset({"password"}), 10
    )
    assert result == {"note": '{"password":"[REDACTED]"}'}


def test_redact_sensitive_json_percent_encoded_value_not_nested_json() -> None:
    value = "%68ello"
    result = _redact_sensitive_json(
        {"note": value}, frozenset({"password"}), frozenset(), 10
    )
    assert result == {"note": value}


def _nested_json_text(depth: int, key: str, leaf: dict[str, str]) -> str:
    leaf_json = json.dumps(leaf)
    prefix = f'{{"{key}":' * depth
    suffix = "}" * depth
    return prefix + leaf_json + suffix


async def test_log_activity_header_json_nested_200_redacts_deep_subtree(
    caplog: pytest.LogCaptureFixture,
) -> None:
    header_value = _nested_json_text(200, "n", {"value": "DEEPSECRET200"})
    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Deep": header_value},
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.WARNING):
        await log_activity(request, logger)

    assert "DEEPSECRET200" not in caplog.text
    assert "[REDACTED]" in caplog.text


async def test_log_activity_header_json_nested_600_does_not_raise_and_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    header_value = _nested_json_text(600, "n", {"value": "DEEPSECRET600"})
    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Deep": header_value},
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.WARNING):
        await log_activity(request, logger)

    assert caplog.records, "log line was not emitted"
    assert "DEEPSECRET600" not in caplog.text
    assert "[REDACTED]" in caplog.text


async def test_log_activity_header_json_nested_5000_does_not_raise_and_logs_fast(
    caplog: pytest.LogCaptureFixture,
) -> None:
    header_value = _nested_json_text(5000, "n", {"value": "DEEPSECRET5000"})
    request = MockGuardRequest(
        path="/",
        method="GET",
        headers={"X-Deep": header_value},
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    durations_ms = []
    for _ in range(5):
        start = time.process_time()
        with caplog.at_level(logging.WARNING):
            await log_activity(request, logger)
        durations_ms.append((time.process_time() - start) * 1000)

    assert caplog.records, "log line was not emitted"
    assert "DEEPSECRET5000" not in caplog.text
    assert "[REDACTED]" in caplog.text
    assert min(durations_ms) < 50


async def test_log_activity_query_json_nested_600_does_not_raise_and_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    query_value = quote_plus(_nested_json_text(600, "n", {"value": "DEEPSECRETQ600"}))
    request = MockGuardRequest(
        path=f"/api?data={query_value}",
        method="GET",
        client_host="127.0.0.1",
    )

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.WARNING):
        await log_activity(request, logger)

    assert caplog.records, "log line was not emitted"
    assert "DEEPSECRETQ600" not in caplog.text
    assert "REDACTED" in caplog.text


def test_redact_sensitive_headers_recursion_guard_redacts_whole_value() -> None:
    header_value = _nested_json_text(5000, "n", {"value": "S"})
    result = _redact_sensitive_headers({"X-Deep": header_value}, None)
    assert result == {"X-Deep": "[REDACTED]"}


def test_redact_endpoint_for_display_leaves_bare_path_unchanged() -> None:
    assert redact_endpoint_for_display("/api/test", None, None) == "/api/test"


def test_redact_endpoint_for_display_redacts_matrix_parameter() -> None:
    result = redact_endpoint_for_display("/items;token=S", None, None)
    assert result == "/items;token=[REDACTED]"


def test_redact_endpoint_for_display_redacts_json_path_segment() -> None:
    result = redact_endpoint_for_display('/items/{"password":"S"}', None, None)
    assert "S" not in result
    assert "REDACTED" in result


def test_redact_header_value_for_display_empty_value_unchanged() -> None:
    assert redact_header_value_for_display("", None, None) == ""


def test_redact_header_value_for_display_leaves_bare_value_unchanged() -> None:
    assert redact_header_value_for_display("Mozilla/5.0", None, None) == "Mozilla/5.0"


def test_redact_header_value_for_display_redacts_json_user_agent() -> None:
    value = '{"password":"S"}'
    result = redact_header_value_for_display(value, None, None)
    assert result == '{"password":"[REDACTED]"}'


def test_redact_header_value_for_display_pair_after_space_redacted() -> None:
    result = redact_header_value_for_display("Bearer x token=SECRET", None, None)
    assert result == "Bearer x token=[REDACTED]"


def test_redact_header_value_for_display_pair_after_tab_redacted() -> None:
    result = redact_header_value_for_display("x\ttoken=SECRET", None, None)
    assert result == "x\ttoken=[REDACTED]"


def test_sanitize_for_log_output_is_ascii_and_cp1252_safe() -> None:
    """_sanitize_for_log must produce pure ASCII so detection log lines can
    never raise UnicodeEncodeError on legacy consoles (Windows cp1252)."""
    from guard_core._utils.logging_utils import _sanitize_for_log

    pdf_with_binary = (
        b"%PDF-1.4\n%\xc7\x8f\xa2\n7 0 obj\n<</Length 8 0 R/Filter /FlateDecode>>"
    )
    value = pdf_with_binary.decode("utf-8", errors="surrogateescape")

    sanitized = _sanitize_for_log(value)

    sanitized.encode("cp1252")  # must not raise
    sanitized.encode("ascii")  # must not raise
    assert "\n" not in sanitized
    assert "\\x9c" in sanitized or "\\u" in sanitized
    assert _sanitize_for_log("plain ascii 123") == "plain ascii 123"
