import warnings
from typing import Any

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.decorators import SecurityDecorator
from guard_core.sync.handlers.behavior_handler import BehaviorRule, BehaviorTracker


def _decorator(**flag: bool) -> SecurityDecorator:
    return SecurityDecorator(SecurityConfig(enable_redis=False, **flag))


def _decorate(decorator: SecurityDecorator, *args: Any, **kwargs: Any) -> Any:
    def route() -> None:
        pass

    return decorator.suspicious_frequency(*args, **kwargs)(route)


BAD_VALUES = [(0.001, 300), (0.5, 1), (0, 300), (1.0, 0), (-1.0, 300)]


@pytest.mark.parametrize(("frequency", "window"), BAD_VALUES)
class TestThresholdBelowOne:
    def test_unset_flag_warns_naming_the_values(
        self, frequency: float, window: int
    ) -> None:
        with pytest.warns(DeprecationWarning) as caught:
            _decorate(_decorator(), frequency, window)

        message = str(caught[0].message)
        assert (
            f"@suspicious_frequency(max_frequency={frequency}, window={window})"
            in message
        )
        assert "every request would trip the rule" in message
        assert "fail_on_misconfiguration is not set" in message

    def test_true_raises_and_leaves_no_route_config(
        self, frequency: float, window: int
    ) -> None:
        decorator = _decorator(fail_on_misconfiguration=True)

        with pytest.raises(ValueError, match="@suspicious_frequency"):
            _decorate(decorator, frequency, window)

        assert decorator._route_configs == {}

    def test_false_warns_without_the_not_set_part(
        self, frequency: float, window: int
    ) -> None:
        with pytest.warns(DeprecationWarning, match="keeps starting") as caught:
            _decorate(_decorator(fail_on_misconfiguration=False), frequency, window)

        assert "is not set" not in str(caught[0].message)

    def test_the_rule_is_still_built_with_the_truncated_threshold(
        self, frequency: float, window: int
    ) -> None:
        decorator = _decorator(fail_on_misconfiguration=False)

        with pytest.warns(DeprecationWarning):
            decorated = _decorate(decorator, frequency, window)

        config = decorator.get_route_config(decorated._guard_route_id)
        assert config is not None
        assert config.behavior_rules[0].threshold == int(frequency * window)


@pytest.mark.parametrize(
    ("frequency", "window", "threshold"),
    [(1.0, 1, 1), (1.9, 1, 1), (0.1, 10, 1), (2.0, 300, 600)],
)
def test_valid_values_never_warn_and_keep_the_threshold(
    frequency: float, window: int, threshold: int
) -> None:
    decorator = _decorator(fail_on_misconfiguration=True)

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        decorated = _decorate(decorator, frequency, window)

    config = decorator.get_route_config(decorated._guard_route_id)
    assert config is not None
    assert config.behavior_rules[0].threshold == threshold


def test_a_threshold_of_zero_trips_on_the_first_request() -> None:
    tracker = BehaviorTracker(SecurityConfig(enable_redis=False))
    rule = BehaviorRule(rule_type="frequency", threshold=0, window=300)

    assert tracker.track_endpoint_usage("ep", "203.0.113.9", rule) is True
