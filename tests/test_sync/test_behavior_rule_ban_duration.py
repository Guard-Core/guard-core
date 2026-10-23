import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.behavior_handler import BehaviorRule, BehaviorTracker


def test_behavior_rule_ban_duration_defaults_to_none() -> None:
    rule = BehaviorRule(rule_type="usage", threshold=5)
    assert rule.ban_duration is None


def test_behavior_rule_ban_duration_accepts_int() -> None:
    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=10,
        pattern="status:404",
        action="ban",
        ban_duration=7200,
    )
    assert rule.ban_duration == 7200


def test_execute_ban_action_uses_rule_ban_duration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracker = BehaviorTracker(SyncSecurityConfig())
    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=1,
        pattern="status:404",
        action="ban",
        ban_duration=7200,
    )
    captured: dict[str, object] = {}

    def fake_ban(ip: str, duration: int, reason: str, *, grouped: bool = False) -> None:
        captured["ip"] = ip
        captured["duration"] = duration
        captured["reason"] = reason

    monkeypatch.setattr(
        "guard_core.sync.handlers.ipban_handler.ip_ban_manager._ban_ip_escalating",
        fake_ban,
    )
    tracker._execute_ban_action("1.2.3.4", "details", rule)
    assert captured["duration"] == 7200


def test_execute_ban_action_defaults_to_3600_when_rule_has_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracker = BehaviorTracker(SyncSecurityConfig())
    rule = BehaviorRule(rule_type="usage", threshold=1, action="ban")
    captured: dict[str, object] = {}

    def fake_ban(ip: str, duration: int, reason: str, *, grouped: bool = False) -> None:
        captured["duration"] = duration

    monkeypatch.setattr(
        "guard_core.sync.handlers.ipban_handler.ip_ban_manager._ban_ip_escalating",
        fake_ban,
    )
    tracker._execute_ban_action("1.2.3.4", "details", rule)
    assert captured["duration"] == 3600


def test_execute_ban_action_defaults_to_3600_when_no_rule_passed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracker = BehaviorTracker(SyncSecurityConfig())
    captured: dict[str, object] = {}

    def fake_ban(ip: str, duration: int, reason: str, *, grouped: bool = False) -> None:
        captured["duration"] = duration

    monkeypatch.setattr(
        "guard_core.sync.handlers.ipban_handler.ip_ban_manager._ban_ip_escalating",
        fake_ban,
    )
    tracker._execute_ban_action("1.2.3.4", "details")
    assert captured["duration"] == 3600
