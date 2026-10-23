from typing import Any

import pytest

from guard_core.models import (
    BehaviorRuleConfig,
    SyncSecurityConfig,
    return_pattern_requires_response_body,
)


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        ("status:200", False),
        ("status:404", False),
        ("json:status==ok", True),
        ("regex:err.*", True),
        ("plain substring", True),
    ],
)
def test_return_pattern_requires_response_body(pattern: str, expected: bool) -> None:
    assert return_pattern_requires_response_body(pattern) is expected


def test_behavior_rule_config_minimum_fields() -> None:
    rule = BehaviorRuleConfig(rule_type="usage", threshold=10)
    assert rule.rule_type == "usage"
    assert rule.threshold == 10
    assert rule.window == 3600
    assert rule.pattern is None
    assert rule.action == "log"
    assert rule.ban_duration is None
    assert rule.correlate_with_detection is False


def test_behavior_rule_config_accepts_all_fields() -> None:
    rule = BehaviorRuleConfig(
        rule_type="return_pattern",
        threshold=20,
        window=300,
        pattern="status:404",
        action="ban",
        ban_duration=7200,
        correlate_with_detection=True,
    )
    assert rule.rule_type == "return_pattern"
    assert rule.pattern == "status:404"
    assert rule.ban_duration == 7200
    assert rule.correlate_with_detection is True


def test_behavior_rule_config_rejects_invalid_rule_type() -> None:
    with pytest.raises(ValueError):
        BehaviorRuleConfig(**{"rule_type": "not_a_type", "threshold": 5})


def test_behavior_rule_config_rejects_invalid_action() -> None:
    with pytest.raises(ValueError):
        BehaviorRuleConfig(**{"rule_type": "usage", "threshold": 5, "action": "nuke"})


def test_behavior_rule_config_rejects_non_positive_threshold() -> None:
    with pytest.raises(ValueError):
        BehaviorRuleConfig(rule_type="usage", threshold=0)


def test_behavior_rule_config_rejects_non_positive_window() -> None:
    with pytest.raises(ValueError):
        BehaviorRuleConfig(rule_type="usage", threshold=1, window=0)


def test_behavior_rule_config_rejects_non_positive_ban_duration() -> None:
    with pytest.raises(ValueError):
        BehaviorRuleConfig(rule_type="usage", threshold=1, ban_duration=0)


def test_security_config_global_behavior_rules_default_empty() -> None:
    assert SyncSecurityConfig().global_behavior_rules == ()


def test_security_config_accepts_global_rules() -> None:
    config = SyncSecurityConfig(
        global_behavior_rules=[
            BehaviorRuleConfig(
                rule_type="return_pattern",
                threshold=20,
                window=300,
                pattern="status:404",
                action="ban",
                ban_duration=3600,
                correlate_with_detection=True,
            )
        ]
    )
    assert len(config.global_behavior_rules) == 1
    assert config.global_behavior_rules[0].pattern == "status:404"


def test_behavior_scan_response_body_defaults_false() -> None:
    assert SyncSecurityConfig().behavior_scan_response_body is False


def test_behavior_max_response_body_inspect_bytes_default() -> None:
    assert SyncSecurityConfig().behavior_max_response_body_inspect_bytes == 262144


@pytest.mark.parametrize(
    "pattern",
    ["error", "json:status==ok", "regex:err.*", "not found"],
)
def test_global_body_return_pattern_rejected_when_body_scan_disabled(
    pattern: str,
) -> None:
    with pytest.raises(ValueError, match="behavior_scan_response_body"):
        SyncSecurityConfig(
            global_behavior_rules=[
                BehaviorRuleConfig(
                    rule_type="return_pattern", threshold=5, pattern=pattern
                )
            ]
        )


@pytest.mark.parametrize(
    "pattern",
    ["error", "json:status==ok", "regex:err.*", "not found"],
)
def test_global_body_return_pattern_accepted_when_body_scan_enabled(
    pattern: str,
) -> None:
    config = SyncSecurityConfig(
        behavior_scan_response_body=True,
        global_behavior_rules=[
            BehaviorRuleConfig(rule_type="return_pattern", threshold=5, pattern=pattern)
        ],
    )
    assert config.global_behavior_rules[0].pattern == pattern


def test_global_status_return_pattern_accepted_when_body_scan_disabled() -> None:
    config = SyncSecurityConfig(
        global_behavior_rules=[
            BehaviorRuleConfig(
                rule_type="return_pattern", threshold=5, pattern="status:404"
            )
        ]
    )
    assert config.global_behavior_rules[0].pattern == "status:404"


def test_global_return_pattern_rule_without_pattern_ignored_by_validator() -> None:
    config = SyncSecurityConfig(
        global_behavior_rules=[
            BehaviorRuleConfig(rule_type="return_pattern", threshold=5),
        ]
    )
    assert config.global_behavior_rules[0].pattern is None


def test_global_usage_rule_ignored_by_body_scan_validator() -> None:
    config = SyncSecurityConfig(
        global_behavior_rules=[
            BehaviorRuleConfig(rule_type="usage", threshold=5),
            BehaviorRuleConfig(rule_type="frequency", threshold=5),
        ]
    )
    assert len(config.global_behavior_rules) == 2


def test_global_behavior_rules_is_stored_as_tuple() -> None:
    config = SyncSecurityConfig(
        global_behavior_rules=[BehaviorRuleConfig(rule_type="usage", threshold=5)]
    )
    assert isinstance(config.global_behavior_rules, tuple)


def test_global_behavior_rules_append_is_rejected_outright() -> None:
    config = SyncSecurityConfig()
    rules: Any = config.global_behavior_rules

    with pytest.raises(AttributeError):
        rules.append(BehaviorRuleConfig(rule_type="usage", threshold=1))


def test_global_rules_assignment_rejects_body_pattern_when_scan_off() -> None:
    config = SyncSecurityConfig(behavior_scan_response_body=False)

    with pytest.raises(ValueError, match="behavior_scan_response_body"):
        config.global_behavior_rules = (
            BehaviorRuleConfig(
                rule_type="return_pattern", threshold=1, pattern="json:x"
            ),
        )


def test_global_rules_assignment_accepts_body_pattern_when_scan_on() -> None:
    config = SyncSecurityConfig(behavior_scan_response_body=True)

    config.global_behavior_rules = (
        BehaviorRuleConfig(rule_type="return_pattern", threshold=1, pattern="json:x"),
    )

    assert config.global_behavior_rules[0].pattern == "json:x"


def test_global_rules_assignment_accepts_status_pattern_when_scan_off() -> None:
    config = SyncSecurityConfig(behavior_scan_response_body=False)

    config.global_behavior_rules = (
        BehaviorRuleConfig(
            rule_type="return_pattern", threshold=1, pattern="status:500"
        ),
    )

    assert config.global_behavior_rules[0].pattern == "status:500"


def test_global_rules_assignment_accepts_usage_rule_when_scan_off() -> None:
    config = SyncSecurityConfig(behavior_scan_response_body=False)

    config.global_behavior_rules = (BehaviorRuleConfig(rule_type="usage", threshold=1),)

    assert config.global_behavior_rules[0].rule_type == "usage"


def test_global_rules_assignment_accepts_return_pattern_without_pattern() -> None:
    config = SyncSecurityConfig(behavior_scan_response_body=False)

    config.global_behavior_rules = (
        BehaviorRuleConfig(rule_type="return_pattern", threshold=1),
    )

    assert config.global_behavior_rules[0].pattern is None


def test_global_rules_assignment_rejection_leaves_state_unchanged() -> None:
    config = SyncSecurityConfig(behavior_scan_response_body=False)
    revision_before = config.revision

    with pytest.raises(ValueError):
        config.global_behavior_rules = (
            BehaviorRuleConfig(
                rule_type="return_pattern", threshold=1, pattern="json:x"
            ),
        )

    assert config.global_behavior_rules == ()
    assert config.revision == revision_before


def test_scan_flag_assignment_rejects_disabling_with_body_pattern_rules() -> None:
    config = SyncSecurityConfig(
        behavior_scan_response_body=True,
        global_behavior_rules=[
            BehaviorRuleConfig(
                rule_type="return_pattern", threshold=1, pattern="json:x"
            )
        ],
    )

    with pytest.raises(ValueError, match="behavior_scan_response_body"):
        config.behavior_scan_response_body = False


def test_scan_flag_assignment_accepts_disabling_without_body_pattern_rules() -> None:
    config = SyncSecurityConfig(
        behavior_scan_response_body=True,
        global_behavior_rules=[
            BehaviorRuleConfig(
                rule_type="return_pattern", threshold=1, pattern="status:404"
            ),
            BehaviorRuleConfig(rule_type="usage", threshold=1),
        ],
    )

    config.behavior_scan_response_body = False

    assert config.behavior_scan_response_body is False


def test_behavior_scan_response_body_runtime_assignment_accepts_enabling() -> None:
    config = SyncSecurityConfig(behavior_scan_response_body=False)

    config.behavior_scan_response_body = True

    assert config.behavior_scan_response_body is True


def test_scan_flag_assignment_rejection_leaves_state_unchanged() -> None:
    config = SyncSecurityConfig(
        behavior_scan_response_body=True,
        global_behavior_rules=[
            BehaviorRuleConfig(
                rule_type="return_pattern", threshold=1, pattern="json:x"
            )
        ],
    )
    revision_before = config.revision

    with pytest.raises(ValueError):
        config.behavior_scan_response_body = False

    assert config.behavior_scan_response_body is True
    assert config.revision == revision_before


def test_model_copy_update_rejects_body_pattern_rule_when_scan_off() -> None:
    base = SyncSecurityConfig(behavior_scan_response_body=False)

    with pytest.raises(ValueError, match="behavior_scan_response_body"):
        base.model_copy(
            update={
                "global_behavior_rules": [
                    BehaviorRuleConfig(
                        rule_type="return_pattern", threshold=1, pattern="json:x"
                    )
                ]
            }
        )


def test_model_copy_update_accepts_usage_global_behavior_rule() -> None:
    base = SyncSecurityConfig()

    copied = base.model_copy(
        update={
            "global_behavior_rules": [
                BehaviorRuleConfig(rule_type="usage", threshold=1)
            ]
        }
    )

    assert copied.global_behavior_rules[0].rule_type == "usage"


def test_model_copy_update_accepts_return_pattern_rule_without_pattern() -> None:
    base = SyncSecurityConfig()

    copied = base.model_copy(
        update={
            "global_behavior_rules": [
                BehaviorRuleConfig(rule_type="return_pattern", threshold=1)
            ]
        }
    )

    assert copied.global_behavior_rules[0].pattern is None


def test_model_copy_update_accepts_status_pattern_rule_when_scan_off() -> None:
    base = SyncSecurityConfig(behavior_scan_response_body=False)

    copied = base.model_copy(
        update={
            "global_behavior_rules": [
                BehaviorRuleConfig(
                    rule_type="return_pattern", threshold=1, pattern="status:404"
                )
            ]
        }
    )

    assert copied.global_behavior_rules[0].pattern == "status:404"


def test_model_copy_update_disabling_scan_rejects_existing_body_pattern_rules() -> None:
    base = SyncSecurityConfig(
        behavior_scan_response_body=True,
        global_behavior_rules=[
            BehaviorRuleConfig(
                rule_type="return_pattern", threshold=1, pattern="json:x"
            )
        ],
    )

    with pytest.raises(ValueError, match="behavior_scan_response_body"):
        base.model_copy(update={"behavior_scan_response_body": False})

    assert base.behavior_scan_response_body is True


def test_model_copy_update_without_global_behavior_fields_skips_revalidation() -> None:
    base = SyncSecurityConfig(
        behavior_scan_response_body=True,
        global_behavior_rules=[
            BehaviorRuleConfig(
                rule_type="return_pattern", threshold=1, pattern="json:x"
            )
        ],
    )

    copied = base.model_copy(update={"rate_limit": 999})

    assert copied.rate_limit == 999
    assert copied.global_behavior_rules == base.global_behavior_rules
