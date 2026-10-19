import logging
import warnings
from collections.abc import Callable
from typing import Any

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.decorators import SecurityDecorator


def _decorator(**flag: bool) -> SecurityDecorator:
    return SecurityDecorator(SecurityConfig(enable_redis=False, **flag))


def _decorate(
    decorator: SecurityDecorator, make: Callable[[SecurityDecorator], Any]
) -> Any:
    def route() -> None:
        pass

    return make(decorator)(route)


BAD_VALUES: list[tuple[Callable[[SecurityDecorator], Any], str]] = [
    (
        lambda d: d.time_window("25:00", "17:00"),
        "@time_window start_time '25:00' is not a valid HH:MM time",
    ),
    (
        lambda d: d.time_window("09:00", "later"),
        "@time_window end_time 'later' is not a valid HH:MM time",
    ),
    (
        lambda d: d.time_window("09:00", "17:00", "Mars/Olympus"),
        "@time_window timezone 'Mars/Olympus' is not a known IANA time zone",
    ),
]


@pytest.mark.parametrize(("make", "problem"), BAD_VALUES)
class TestBadRouteArgument:
    def test_unset_flag_refuses_naming_the_value_and_the_old_value(
        self, make: Callable[[SecurityDecorator], Any], problem: str
    ) -> None:
        with pytest.raises(ValueError) as caught:
            _decorate(_decorator(), make)

        message = str(caught.value)
        assert problem in message
        assert "fail_on_misconfiguration=False" in message

    def test_true_raises_and_leaves_no_route_config(
        self, make: Callable[[SecurityDecorator], Any], problem: str
    ) -> None:
        decorator = _decorator(fail_on_misconfiguration=True)

        with pytest.raises(ValueError) as caught:
            _decorate(decorator, make)

        assert problem in str(caught.value)
        assert decorator._route_configs == {}

    def test_false_logs_one_warning_and_starts(
        self,
        make: Callable[[SecurityDecorator], Any],
        problem: str,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="guard_core"):
            with warnings.catch_warnings():
                warnings.simplefilter("error")
                _decorate(_decorator(fail_on_misconfiguration=False), make)

        messages = [r.getMessage() for r in caplog.records if problem in r.message]
        assert len(messages) == 1
        assert "keeps starting" in messages[0]


@pytest.mark.parametrize(
    "make",
    [
        lambda d: d.time_window("9:00", "17:00", "Europe/Madrid"),
        lambda d: d.time_window("22:00", "06:00"),
    ],
)
def test_valid_values_never_warn(make: Callable[[SecurityDecorator], Any]) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _decorate(_decorator(fail_on_misconfiguration=True), make)
