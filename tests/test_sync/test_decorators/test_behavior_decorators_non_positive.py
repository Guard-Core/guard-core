from collections.abc import Callable

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.decorators import SecurityDecorator
from guard_core.sync.handlers.behavior_handler import BehaviorRule


def _target() -> None:
    pass


def _decorator(*, refuse: bool) -> SecurityDecorator:
    return SecurityDecorator(
        SyncSecurityConfig(enable_redis=False, fail_on_misconfiguration=refuse)
    )


Build = Callable[[SecurityDecorator], Callable[[Callable[[], None]], object]]


@pytest.mark.parametrize(
    "build",
    [
        lambda d: d.usage_monitor(0, 0),
        lambda d: d.usage_monitor(-5, -5),
        lambda d: d.usage_monitor(3, 0),
        lambda d: d.usage_monitor(0, 60),
        lambda d: d.return_monitor("status:200", 0, 0),
        lambda d: d.return_monitor("status:200", 5, -1),
        lambda d: d.behavior_analysis([BehaviorRule("usage", 0, 0)]),
    ],
)
def test_a_threshold_or_window_below_one_is_refused(build: Build) -> None:
    decorator = _decorator(refuse=True)

    with pytest.raises(ValueError, match="at least 1"):
        build(decorator)(_target)


def test_a_valid_rule_is_accepted() -> None:
    decorated = _decorator(refuse=True).usage_monitor(3, 60)(_target)

    assert decorated is _target


def test_a_bad_rule_only_warns_when_the_refusal_is_off(
    caplog: pytest.LogCaptureFixture,
) -> None:
    decorated = _decorator(refuse=False).usage_monitor(0, 0)(_target)

    assert decorated is _target
    assert "at least 1" in caplog.text
