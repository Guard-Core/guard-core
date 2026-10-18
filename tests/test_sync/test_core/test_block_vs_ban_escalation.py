from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.checks.implementations.ip_security import IpSecurityCheck
from guard_core.sync.core.checks.implementations.user_agent import UserAgentCheck
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.detection_result import DetectionResult
from guard_core.sync.utils import IpAccessResult


def _make_middleware(config: SecurityConfig) -> MagicMock:
    mw = MagicMock()
    mw.config = config
    mw.logger = MagicMock()
    mw.event_bus = MagicMock()
    mw.event_bus.send_middleware_event = MagicMock()
    mw.create_error_response = MagicMock(return_value=MagicMock(status_code=403))
    mw.route_resolver = MagicMock()
    mw.route_resolver.should_bypass_check = MagicMock(return_value=False)
    mw.geo_ip_handler = None
    mw.suspicious_request_counts = {}
    return mw


def _make_request(client_ip: str | None = "1.2.3.4") -> MagicMock:
    request = MagicMock()
    request.state = MagicMock()
    request.state.client_ip = client_ip
    request.state.route_config = None
    request.state.is_whitelisted = False
    request.headers = {"User-Agent": "badbot"}
    request.url_full = "https://test/x"
    return request


def _patch_detect_threat(
    monkeypatch: pytest.MonkeyPatch,
    is_threat: bool = True,
    trigger_info: str = "xss hit",
    threat_categories: list[str] | None = None,
) -> None:
    def fake_detect(*_args: Any, **_kwargs: Any) -> DetectionResult:
        return DetectionResult(
            is_threat=is_threat,
            trigger_info=trigger_info,
            threat_categories=threat_categories
            if threat_categories is not None
            else ["xss"],
        )

    monkeypatch.setattr(
        "guard_core.sync.core.checks.helpers.detect_penetration_patterns", fake_detect
    )


def test_global_ip_block_with_threat_increments_counter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False, enable_ip_banning=True, auto_ban_threshold=1000
    )
    mw = _make_middleware(config)
    check = IpSecurityCheck(mw)
    request = _make_request("20.0.0.1")
    ban = MagicMock()
    check.ip_ban_manager = ban

    with (
        patch(
            "guard_core.sync.core.checks.implementations.ip_security.check_ip_access",
            return_value=IpAccessResult(False, "blocked"),
        ),
        patch("guard_core.sync.core.checks.implementations.ip_security.log_activity"),
    ):
        _patch_detect_threat(monkeypatch)
        result = check._check_global_ip_restrictions(request, "20.0.0.1")

    assert result is not None
    assert mw.suspicious_request_counts["20.0.0.1"] == {"xss": 1}
    ban.ban_ip.assert_not_called()


def test_global_ip_block_with_threat_repeated_triggers_ban(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False,
        enable_ip_banning=True,
        auto_ban_threshold=2,
        auto_ban_duration=300,
    )
    mw = _make_middleware(config)
    check = IpSecurityCheck(mw)
    ban = MagicMock()
    check.ip_ban_manager = ban

    with (
        patch(
            "guard_core.sync.core.checks.implementations.ip_security.check_ip_access",
            return_value=IpAccessResult(False, "blocked"),
        ),
        patch("guard_core.sync.core.checks.implementations.ip_security.log_activity"),
    ):
        _patch_detect_threat(monkeypatch)
        check._check_global_ip_restrictions(_make_request("21.0.0.1"), "21.0.0.1")
        assert ban.ban_ip.call_count == 0
        check._check_global_ip_restrictions(_make_request("21.0.0.1"), "21.0.0.1")

    ban.ban_ip.assert_called_once_with(
        "21.0.0.1", 300, "penetration_attempt", grouped=False
    )


def test_global_ip_block_no_threat_no_counter_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False, enable_ip_banning=True, auto_ban_threshold=1
    )
    mw = _make_middleware(config)
    check = IpSecurityCheck(mw)
    ban = MagicMock()
    check.ip_ban_manager = ban

    with (
        patch(
            "guard_core.sync.core.checks.implementations.ip_security.check_ip_access",
            return_value=IpAccessResult(False, "blocked"),
        ),
        patch("guard_core.sync.core.checks.implementations.ip_security.log_activity"),
    ):
        _patch_detect_threat(monkeypatch, is_threat=False, trigger_info="not_enabled")
        result = check._check_global_ip_restrictions(
            _make_request("22.0.0.1"), "22.0.0.1"
        )

    assert result is not None
    assert mw.suspicious_request_counts == {}
    ban.ban_ip.assert_not_called()


def test_global_ip_block_passive_mode_no_escalation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=True, enable_ip_banning=True, auto_ban_threshold=1
    )
    mw = _make_middleware(config)
    check = IpSecurityCheck(mw)
    ban = MagicMock()
    check.ip_ban_manager = ban

    detect_called: list[int] = []

    def spy_detect(*_args: Any, **_kwargs: Any) -> DetectionResult:
        detect_called.append(1)
        return DetectionResult(
            is_threat=True, trigger_info="t", threat_categories=["xss"]
        )

    monkeypatch.setattr(
        "guard_core.sync.core.checks.helpers.detect_penetration_patterns", spy_detect
    )

    with (
        patch(
            "guard_core.sync.core.checks.implementations.ip_security.check_ip_access",
            return_value=IpAccessResult(False, "blocked"),
        ),
        patch("guard_core.sync.core.checks.implementations.ip_security.log_activity"),
    ):
        result = check._check_global_ip_restrictions(
            _make_request("23.0.0.1"), "23.0.0.1"
        )

    assert result is None
    assert mw.suspicious_request_counts == {}
    ban.ban_ip.assert_not_called()
    assert detect_called == []


def test_globally_whitelisted_ip_blocked_by_route_whitelist_is_not_whitelisted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False,
        enable_ip_banning=True,
        auto_ban_threshold=1,
        whitelist=["24.0.0.1"],
    )
    mw = _make_middleware(config)
    check = IpSecurityCheck(mw)
    ban = MagicMock()
    ban.is_ip_banned = MagicMock(return_value=False)
    check.ip_ban_manager = ban

    route_config = RouteConfig()
    route_config.ip_whitelist = ["9.9.9.9"]
    request = _make_request("24.0.0.1")
    request.state.route_config = route_config

    with patch("guard_core.sync.core.checks.implementations.ip_security.log_activity"):
        _patch_detect_threat(monkeypatch, is_threat=False, trigger_info="not_enabled")
        result = check.check(request)

    assert result is not None
    assert result.status_code == 403
    assert request.state.is_whitelisted is False
    assert mw.suspicious_request_counts == {}
    ban.ban_ip.assert_not_called()


def test_global_whitelist_blocked_by_stricter_route_whitelist_escalates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False,
        enable_ip_banning=True,
        auto_ban_threshold=1,
        whitelist=["203.0.113.0/24"],
    )
    mw = _make_middleware(config)
    check = IpSecurityCheck(mw)
    ban = MagicMock()
    ban.is_ip_banned = MagicMock(return_value=False)
    check.ip_ban_manager = ban

    route_config = RouteConfig()
    route_config.ip_whitelist = ["10.0.0.1"]
    request = _make_request("203.0.113.55")
    request.state.route_config = route_config

    with patch("guard_core.sync.core.checks.implementations.ip_security.log_activity"):
        _patch_detect_threat(
            monkeypatch,
            is_threat=True,
            trigger_info="sqli hit",
            threat_categories=["sqli"],
        )
        result = check.check(request)

    assert result is not None
    assert result.status_code == 403
    assert request.state.is_whitelisted is False
    assert "203.0.113.55" not in mw.suspicious_request_counts
    ban.ban_ip.assert_called_once_with(
        "203.0.113.55", config.auto_ban_duration, "penetration_attempt", grouped=False
    )


def test_global_whitelist_blocked_by_route_blacklist_still_escalates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False,
        enable_ip_banning=True,
        auto_ban_threshold=1,
        whitelist=["203.0.113.0/24"],
    )
    mw = _make_middleware(config)
    check = IpSecurityCheck(mw)
    ban = MagicMock()
    ban.is_ip_banned = MagicMock(return_value=False)
    check.ip_ban_manager = ban

    route_config = RouteConfig()
    route_config.ip_blacklist = ["203.0.113.55"]
    request = _make_request("203.0.113.55")
    request.state.route_config = route_config

    with patch("guard_core.sync.core.checks.implementations.ip_security.log_activity"):
        _patch_detect_threat(
            monkeypatch,
            is_threat=True,
            trigger_info="sqli hit",
            threat_categories=["sqli"],
        )
        result = check.check(request)

    assert result is not None
    assert result.status_code == 403
    assert "203.0.113.55" not in mw.suspicious_request_counts
    ban.ban_ip.assert_called_once_with(
        "203.0.113.55", config.auto_ban_duration, "penetration_attempt", grouped=False
    )


def test_route_blacklist_without_global_whitelist_escalates_as_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False,
        enable_ip_banning=True,
        auto_ban_threshold=1,
    )
    mw = _make_middleware(config)
    check = IpSecurityCheck(mw)
    ban = MagicMock()
    ban.is_ip_banned = MagicMock(return_value=False)
    check.ip_ban_manager = ban

    route_config = RouteConfig()
    route_config.ip_blacklist = ["203.0.113.55"]
    request = _make_request("203.0.113.55")
    request.state.route_config = route_config

    with patch("guard_core.sync.core.checks.implementations.ip_security.log_activity"):
        _patch_detect_threat(
            monkeypatch,
            is_threat=True,
            trigger_info="sqli hit",
            threat_categories=["sqli"],
        )
        result = check.check(request)

    assert result is not None
    assert result.status_code == 403
    assert "203.0.113.55" not in mw.suspicious_request_counts
    ban.ban_ip.assert_called_once_with(
        "203.0.113.55", config.auto_ban_duration, "penetration_attempt", grouped=False
    )


def test_global_whitelist_and_route_whitelist_both_containing_ip_is_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False,
        enable_ip_banning=True,
        auto_ban_threshold=1,
        whitelist=["203.0.113.0/24"],
    )
    mw = _make_middleware(config)
    check = IpSecurityCheck(mw)
    ban = MagicMock()
    ban.is_ip_banned = MagicMock(return_value=False)
    check.ip_ban_manager = ban

    route_config = RouteConfig()
    route_config.ip_whitelist = ["203.0.113.55"]
    request = _make_request("203.0.113.55")
    request.state.route_config = route_config

    with patch("guard_core.sync.core.checks.implementations.ip_security.log_activity"):
        _patch_detect_threat(monkeypatch, is_threat=False, trigger_info="not_enabled")
        result = check.check(request)

    assert result is None
    assert mw.suspicious_request_counts == {}
    ban.ban_ip.assert_not_called()


def test_route_ip_block_with_threat_increments_counter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False, enable_ip_banning=True, auto_ban_threshold=1000
    )
    mw = _make_middleware(config)
    check = IpSecurityCheck(mw)
    ban = MagicMock()
    check.ip_ban_manager = ban

    request = _make_request("24.0.0.1")

    with (
        patch(
            "guard_core.sync.core.checks.implementations.ip_security.check_route_ip_access",
            return_value=False,
        ),
        patch("guard_core.sync.core.checks.implementations.ip_security.log_activity"),
    ):
        _patch_detect_threat(monkeypatch)
        result = check._check_route_ip_restrictions(request, "24.0.0.1", RouteConfig())

    assert result is not None
    assert mw.suspicious_request_counts["24.0.0.1"] == {"xss": 1}


def test_route_ip_block_no_threat_no_counter_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False, enable_ip_banning=True, auto_ban_threshold=1
    )
    mw = _make_middleware(config)
    check = IpSecurityCheck(mw)
    ban = MagicMock()
    check.ip_ban_manager = ban

    request = _make_request("24.5.0.1")

    with (
        patch(
            "guard_core.sync.core.checks.implementations.ip_security.check_route_ip_access",
            return_value=False,
        ),
        patch("guard_core.sync.core.checks.implementations.ip_security.log_activity"),
    ):
        _patch_detect_threat(monkeypatch, is_threat=False, trigger_info="not_enabled")
        result = check._check_route_ip_restrictions(request, "24.5.0.1", RouteConfig())

    assert result is not None
    assert mw.suspicious_request_counts == {}
    ban.ban_ip.assert_not_called()


def test_route_ip_block_passive_mode_no_escalation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=True, enable_ip_banning=True, auto_ban_threshold=1
    )
    mw = _make_middleware(config)
    check = IpSecurityCheck(mw)
    ban = MagicMock()
    check.ip_ban_manager = ban

    detect_called: list[int] = []

    def spy_detect(*_args: Any, **_kwargs: Any) -> DetectionResult:
        detect_called.append(1)
        return DetectionResult(
            is_threat=True, trigger_info="t", threat_categories=["xss"]
        )

    monkeypatch.setattr(
        "guard_core.sync.core.checks.helpers.detect_penetration_patterns", spy_detect
    )

    with (
        patch(
            "guard_core.sync.core.checks.implementations.ip_security.check_route_ip_access",
            return_value=False,
        ),
        patch("guard_core.sync.core.checks.implementations.ip_security.log_activity"),
    ):
        result = check._check_route_ip_restrictions(
            _make_request("25.0.0.1"), "25.0.0.1", RouteConfig()
        )

    assert result is None
    assert mw.suspicious_request_counts == {}
    assert detect_called == []


def test_user_agent_block_with_threat_increments_counter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False,
        enable_ip_banning=True,
        auto_ban_threshold=1000,
        blocked_user_agents=[r"badbot"],
    )
    mw = _make_middleware(config)
    check = UserAgentCheck(mw)
    ban = MagicMock()
    check.ip_ban_manager = ban
    request = _make_request("26.0.0.1")

    _patch_detect_threat(monkeypatch)

    result = check.check(request)

    assert result is not None
    assert mw.suspicious_request_counts["26.0.0.1"] == {"xss": 1}


def test_user_agent_block_with_threat_repeated_triggers_ban(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False,
        enable_ip_banning=True,
        auto_ban_threshold=2,
        auto_ban_duration=300,
        blocked_user_agents=[r"badbot"],
    )
    mw = _make_middleware(config)
    check = UserAgentCheck(mw)
    ban = MagicMock()
    check.ip_ban_manager = ban

    _patch_detect_threat(monkeypatch)

    check.check(_make_request("27.0.0.1"))
    assert ban.ban_ip.call_count == 0
    check.check(_make_request("27.0.0.1"))
    ban.ban_ip.assert_called_once_with(
        "27.0.0.1", 300, "penetration_attempt", grouped=False
    )


def test_user_agent_block_no_threat_no_counter_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False,
        enable_ip_banning=True,
        auto_ban_threshold=1,
        blocked_user_agents=[r"badbot"],
    )
    mw = _make_middleware(config)
    check = UserAgentCheck(mw)
    ban = MagicMock()
    check.ip_ban_manager = ban

    _patch_detect_threat(monkeypatch, is_threat=False, trigger_info="not_enabled")

    result = check.check(_make_request("28.0.0.1"))

    assert result is not None
    assert mw.suspicious_request_counts == {}
    ban.ban_ip.assert_not_called()


def test_user_agent_block_passive_mode_no_escalation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=True,
        enable_ip_banning=True,
        auto_ban_threshold=1,
        blocked_user_agents=[r"badbot"],
    )
    mw = _make_middleware(config)
    check = UserAgentCheck(mw)
    ban = MagicMock()
    check.ip_ban_manager = ban

    detect_called: list[int] = []

    def spy_detect(*_args: Any, **_kwargs: Any) -> DetectionResult:
        detect_called.append(1)
        return DetectionResult(
            is_threat=True, trigger_info="t", threat_categories=["xss"]
        )

    monkeypatch.setattr(
        "guard_core.sync.core.checks.helpers.detect_penetration_patterns", spy_detect
    )

    result = check.check(_make_request("29.0.0.1"))

    assert result is None
    assert mw.suspicious_request_counts == {}
    assert detect_called == []


def test_user_agent_block_no_client_ip_skips_escalation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False,
        enable_ip_banning=True,
        auto_ban_threshold=1,
        blocked_user_agents=[r"badbot"],
    )
    mw = _make_middleware(config)
    check = UserAgentCheck(mw)
    ban = MagicMock()
    check.ip_ban_manager = ban

    detect_called: list[int] = []

    def spy_detect(*_args: Any, **_kwargs: Any) -> DetectionResult:
        detect_called.append(1)
        return DetectionResult(
            is_threat=True, trigger_info="t", threat_categories=["xss"]
        )

    monkeypatch.setattr(
        "guard_core.sync.core.checks.helpers.detect_penetration_patterns", spy_detect
    )

    result = check.check(_make_request(None))

    assert result is not None
    assert mw.suspicious_request_counts == {}
    assert detect_called == []


def test_no_double_count_blocked_probe_increments_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False,
        enable_ip_banning=True,
        auto_ban_threshold=1000,
        blocked_user_agents=[r"badbot"],
    )
    mw = _make_middleware(config)
    check = UserAgentCheck(mw)
    check.ip_ban_manager = MagicMock()

    detect_calls: list[int] = []

    def counting_detect(*_args: Any, **_kwargs: Any) -> DetectionResult:
        detect_calls.append(1)
        return DetectionResult(
            is_threat=True, trigger_info="t", threat_categories=["xss"]
        )

    monkeypatch.setattr(
        "guard_core.sync.core.checks.helpers.detect_penetration_patterns",
        counting_detect,
    )

    check.check(_make_request("30.0.0.1"))

    assert len(detect_calls) == 1
    assert mw.suspicious_request_counts["30.0.0.1"] == {"xss": 1}


def test_global_ip_block_still_returns_403_when_ban_ip_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False,
        enable_ip_banning=True,
        auto_ban_threshold=1,
        auto_ban_duration=7200,
    )
    mw = _make_middleware(config)
    check = IpSecurityCheck(mw)
    ban = MagicMock()
    ban.ban_ip = MagicMock(side_effect=ValueError("duration exceeds local cap"))
    check.ip_ban_manager = ban

    _patch_detect_threat(monkeypatch)

    with (
        patch(
            "guard_core.sync.core.checks.implementations.ip_security.check_ip_access",
            return_value=IpAccessResult(False, "blocked"),
        ),
        patch("guard_core.sync.core.checks.implementations.ip_security.log_activity"),
    ):
        result = check._check_global_ip_restrictions(
            _make_request("50.0.0.1"), "50.0.0.1"
        )

    assert result is not None
    assert result.status_code == 403
    ban.ban_ip.assert_called_once_with(
        "50.0.0.1", 7200, "penetration_attempt", grouped=False
    )
    mw.logger.exception.assert_called_once()
    assert mw.logger.exception.call_args.args[1] == "50.0.0.1"
    event_call = mw.event_bus.send_middleware_event.call_args
    assert event_call.kwargs["event_type"] == "ip_ban_failed"


def test_user_agent_block_still_returns_403_when_ban_ip_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False,
        enable_ip_banning=True,
        auto_ban_threshold=1,
        auto_ban_duration=7200,
        blocked_user_agents=[r"badbot"],
    )
    mw = _make_middleware(config)
    check = UserAgentCheck(mw)
    ban = MagicMock()
    ban.ban_ip = MagicMock(side_effect=ValueError("duration exceeds local cap"))
    check.ip_ban_manager = ban

    _patch_detect_threat(monkeypatch)

    result = check.check(_make_request("51.0.0.1"))

    assert result is not None
    assert result.status_code == 403
    ban.ban_ip.assert_called_once_with(
        "51.0.0.1", 7200, "penetration_attempt", grouped=False
    )
    mw.logger.exception.assert_called_once()
    assert mw.logger.exception.call_args.args[1] == "51.0.0.1"
    event_call = mw.event_bus.send_middleware_event.call_args
    assert event_call.kwargs["event_type"] == "ip_ban_failed"


def test_global_ip_block_survives_ban_and_event_bus_both_failing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(
        passive_mode=False,
        enable_ip_banning=True,
        auto_ban_threshold=1,
        fail_secure=True,
    )
    mw = _make_middleware(config)
    check = IpSecurityCheck(mw)
    ban = MagicMock()
    ban.ban_ip = MagicMock(side_effect=RuntimeError("redis down, ban not applied"))
    check.ip_ban_manager = ban

    def selective_failure(*_a: Any, **kwargs: Any) -> None:
        if kwargs.get("event_type") == "ip_ban_failed":
            raise ConnectionError("event bus down too")

    mw.event_bus.send_middleware_event = MagicMock(side_effect=selective_failure)

    _patch_detect_threat(monkeypatch)

    with (
        patch(
            "guard_core.sync.core.checks.implementations.ip_security.check_ip_access",
            return_value=IpAccessResult(False, "blocked"),
        ),
        patch("guard_core.sync.core.checks.implementations.ip_security.log_activity"),
    ):
        result = check._check_global_ip_restrictions(
            _make_request("52.0.0.1"), "52.0.0.1"
        )

    assert result is not None
    assert result.status_code == 403
    assert mw.logger.exception.call_count == 2
