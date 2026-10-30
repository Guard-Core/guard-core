import time

import pytest
from pydantic import ValidationError

from guard_core.decorators import SecurityDecorator
from guard_core.handlers.behavior_handler import BehaviorRule
from guard_core.models import BehaviorRuleConfig, SecurityConfig


def _config(pattern: str) -> SecurityConfig:
    rule = BehaviorRuleConfig(
        rule_type="return_pattern", pattern=pattern, threshold=1, action="ban"
    )
    return SecurityConfig(
        global_behavior_rules=(rule,), behavior_scan_response_body=True
    )


@pytest.mark.parametrize(
    "pattern", ["regex:(a+)+$", "regex:(", "status:4xx", "status:"]
)
def test_a_global_rule_with_a_hostile_or_never_matching_pattern_is_refused(
    pattern: str,
) -> None:
    started = time.process_time()
    with pytest.raises(ValidationError) as refusal:
        _config(pattern)
    assert time.process_time() - started < 5
    assert "return_pattern" in str(refusal.value)


@pytest.mark.parametrize(
    "pattern",
    [
        "regex:secret[0-9]+",
        "regex:error|failed",
        "status:404",
        "status: 403",
        "json:a.b",
        "plain text",
    ],
)
def test_a_safe_pattern_is_accepted(pattern: str) -> None:
    assert len(_config(pattern).global_behavior_rules) == 1


def _sample() -> None:
    pass


@pytest.mark.parametrize("pattern", ["regex:(a+)+$", "regex:(", "status:4xx"])
def test_return_monitor_refuses_a_hostile_or_never_matching_pattern(
    pattern: str,
) -> None:
    decorator = SecurityDecorator(SecurityConfig(behavior_scan_response_body=True))

    with pytest.raises(ValueError, match="return_pattern"):
        decorator.return_monitor(pattern, max_occurrences=1)


def test_behavior_analysis_refuses_a_hostile_pattern() -> None:
    decorator = SecurityDecorator(SecurityConfig(behavior_scan_response_body=True))
    rule = BehaviorRule(rule_type="return_pattern", threshold=1, pattern="regex:(a+)+$")

    with pytest.raises(ValueError, match="return_pattern"):
        decorator.behavior_analysis([rule])


def test_return_monitor_accepts_a_safe_regex() -> None:
    decorator = SecurityDecorator(SecurityConfig(behavior_scan_response_body=True))

    decorated = decorator.return_monitor("regex:error[0-9]+", max_occurrences=1)(
        _sample
    )

    assert decorated is _sample
