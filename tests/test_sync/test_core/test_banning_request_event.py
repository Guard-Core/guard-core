import logging
from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig, ThreatBanConfig
from guard_core.sync.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.sync.detection_result import DetectionResult

CLIENT_IP = "203.0.113.20"


def _build(
    monkeypatch: pytest.MonkeyPatch, **fields: object
) -> tuple[SuspiciousActivityCheck, MagicMock]:
    config = SyncSecurityConfig(
        enable_ip_banning=True,
        enable_redis=False,
        rate_limit=1000,
        auto_ban_duration=4321,
        **fields,
    )
    middleware = MagicMock()
    middleware.config = config
    middleware.suspicious_request_counts = {}
    middleware.logger = logging.getLogger("guard_core.test_banning_request_event")
    send_event = MagicMock()
    middleware.event_bus.send_middleware_event = send_event
    middleware.create_error_response = MagicMock(
        return_value=MagicMock(status_code=403)
    )
    middleware.route_resolver.should_bypass_check = lambda *_: False
    check = SuspiciousActivityCheck(middleware)

    def detect(*_args: object, **_kwargs: object) -> DetectionResult:
        return DetectionResult(
            is_threat=True, trigger_info="probe", threat_categories=["xss"]
        )

    def ban(
        ip: str, duration: int, reason: str = "", *, grouped: bool = False
    ) -> int | None:
        return duration

    monkeypatch.setattr(
        "guard_core.sync.core.checks.implementations.suspicious_activity"
        ".get_cached_detection_result",
        detect,
    )
    monkeypatch.setattr(check.ip_ban_manager, "_ban_ip_escalating", ban)
    return check, send_event


def _request() -> MagicMock:
    request = MagicMock()
    request.state.is_whitelisted = False
    request.state.client_ip = CLIENT_IP
    request.state.route_config = None
    request.url_full = "https://test/x"
    return request


def test_the_banning_request_sends_the_penetration_attempt_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    check, send_event = _build(monkeypatch, auto_ban_threshold=2)

    check.check(_request())
    assert send_event.call_args.kwargs["action_taken"] == "request_blocked"
    check.check(_request())

    calls = send_event.call_args_list
    assert [call.kwargs["action_taken"] for call in calls] == [
        "request_blocked",
        "request_blocked",
    ]
    assert calls[1].kwargs["event_type"] == "penetration_attempt"
    assert calls[1].kwargs["request_count"] == 2
    assert calls[1].kwargs["trigger_info"] == "probe"


def test_the_ban_log_names_the_duration(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    check, _ = _build(
        monkeypatch,
        auto_ban_threshold=1,
        threat_ban_config={"xss": ThreatBanConfig(threshold=1, duration=777)},
    )

    with caplog.at_level(logging.WARNING):
        check.check(_request())

    banned = [
        r.getMessage() for r in caplog.records if "IP banned due to" in r.getMessage()
    ]
    assert len(banned) == 1
    assert "(ban duration 777s)" in banned[0]
