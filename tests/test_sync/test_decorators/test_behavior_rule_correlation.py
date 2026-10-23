from guard_core.models import BehaviorRuleConfig, SyncSecurityConfig
from guard_core.sync.handlers.behavior_handler import (
    BehaviorRule,
    BehaviorTracker,
    config_to_rule,
)
from tests.test_sync.conftest import MockGuardResponse


def test_behavior_rule_correlate_default_false() -> None:
    rule = BehaviorRule(rule_type="usage", threshold=10)
    assert rule.correlate_with_detection is False


def test_behavior_rule_correlate_explicit_true() -> None:
    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=20,
        pattern="status:404",
        action="ban",
        correlate_with_detection=True,
    )
    assert rule.correlate_with_detection is True


def test_config_to_rule_round_trip() -> None:
    cfg = BehaviorRuleConfig(
        rule_type="return_pattern",
        threshold=20,
        window=300,
        pattern="status:404",
        action="ban",
        ban_duration=7200,
        correlate_with_detection=True,
    )
    rule = config_to_rule(cfg)
    assert isinstance(rule, BehaviorRule)
    assert rule.rule_type == "return_pattern"
    assert rule.threshold == 20
    assert rule.window == 300
    assert rule.pattern == "status:404"
    assert rule.action == "ban"
    assert rule.ban_duration == 7200
    assert rule.correlate_with_detection is True


def test_track_return_pattern_respects_effective_threshold() -> None:
    tracker = BehaviorTracker(SyncSecurityConfig())
    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=10,
        pattern="status:404",
    )
    response = MockGuardResponse("not found", status_code=404)

    results = [
        tracker.track_return_pattern(
            "ep", "1.2.3.4", response, rule, effective_threshold=2
        )
        for _ in range(3)
    ]
    assert results[0] is False
    assert results[1] is False
    assert results[2] is True


def test_track_return_pattern_uses_rule_threshold_when_override_none() -> None:
    tracker = BehaviorTracker(SyncSecurityConfig())
    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=2,
        pattern="status:404",
    )
    response = MockGuardResponse("not found", status_code=404)

    results = [
        tracker.track_return_pattern("ep2", "1.2.3.4", response, rule) for _ in range(3)
    ]
    assert results == [False, False, True]
