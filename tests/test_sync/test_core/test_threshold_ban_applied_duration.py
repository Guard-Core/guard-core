import time
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig, ThreatBanConfig
from guard_core.sync.core.checks.helpers import _resolve_and_apply_threshold_ban
from guard_core.sync.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.sync.detection_result import DetectionResult
from guard_core.sync.handlers.ipban_handler import IPBanManager

CLIENT_IP = "203.0.113.31"


@pytest.fixture(autouse=True)
def _reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


def _config(**settings: Any) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=False,
        enable_ip_banning=True,
        auto_ban_threshold=1,
        auto_ban_duration=600,
        **settings,
    )


def _manager(config: SyncSecurityConfig) -> IPBanManager:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.config = config
    return manager


def _threshold_ban(
    manager: IPBanManager, config: SyncSecurityConfig
) -> tuple[int, str, str | None] | None:
    return _resolve_and_apply_threshold_ban(
        {"xss": 1},
        config,
        manager,
        CLIENT_IP,
        ("xss",),
        "penetration_attempt",
        flat_total=1,
    )


def test_a_second_threshold_ban_in_the_window_reports_twice_the_duration() -> None:
    config = _config(enable_recidive=True)
    manager = _manager(config)

    first = _threshold_ban(manager, config)
    manager.banned_ips[CLIENT_IP] = time.time() - 1
    second = _threshold_ban(manager, config)

    assert first == (600, "penetration_attempt", None)
    assert second == (1200, "penetration_attempt", None)


def test_a_category_entry_reports_its_escalated_duration_too() -> None:
    config = _config(
        enable_recidive=True,
        threat_ban_config={"xss": ThreatBanConfig(threshold=1, duration=900)},
    )
    manager = _manager(config)

    _threshold_ban(manager, config)
    manager.banned_ips[CLIENT_IP] = time.time() - 1
    second = _threshold_ban(manager, config)

    assert second == (1800, "penetration_attempt:xss", "xss")


def test_without_recidive_the_reported_duration_is_the_configured_one() -> None:
    config = _config()
    manager = _manager(config)

    first = _threshold_ban(manager, config)
    manager.banned_ips[CLIENT_IP] = time.time() - 1
    second = _threshold_ban(manager, config)

    assert first == second == (600, "penetration_attempt", None)


def test_a_refused_ban_is_reported_as_no_ban() -> None:
    config = _config()
    manager = MagicMock()
    manager._ban_ip_escalating = MagicMock(return_value=None)

    assert _threshold_ban(manager, config) is None


def test_the_banning_request_event_and_log_carry_the_applied_duration(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    config = _config(enable_recidive=True, enable_penetration_detection=True)
    middleware = MagicMock()
    middleware.config = config
    middleware.suspicious_request_counts = {}
    middleware.logger = logging.getLogger("guard_core.test_applied_duration")
    send_event = MagicMock()
    middleware.event_bus.send_middleware_event = send_event
    middleware.create_error_response = MagicMock(
        return_value=MagicMock(status_code=403)
    )
    middleware.route_resolver.should_bypass_check = lambda *_: False
    check = SuspiciousActivityCheck(middleware)
    manager = _manager(config)
    check.ip_ban_manager = manager

    def detect(*_args: Any, **_kwargs: Any) -> DetectionResult:
        return DetectionResult(
            is_threat=True, trigger_info="probe", threat_categories=["xss"]
        )

    monkeypatch.setattr(
        "guard_core.sync.core.checks.implementations.suspicious_activity"
        ".get_cached_detection_result",
        detect,
    )

    def request() -> MagicMock:
        item = MagicMock()
        item.state.is_whitelisted = False
        item.state.client_ip = CLIENT_IP
        item.state.route_config = None
        item.url_full = "https://test/x"
        return item

    with caplog.at_level(logging.WARNING):
        check.check(request())
        manager.banned_ips[CLIENT_IP] = time.time() - 1
        check.check(request())

    durations = [call.kwargs["ban_duration"] for call in send_event.call_args_list]
    assert durations == [600, 1200]
    logged = [
        r.getMessage() for r in caplog.records if "IP banned due to" in r.getMessage()
    ]
    assert "(ban duration 600s)" in logged[0]
    assert "(ban duration 1200s)" in logged[1]
