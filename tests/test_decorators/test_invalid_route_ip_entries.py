import logging
import warnings
from collections.abc import Callable
from typing import Any

import pytest

from guard_core.decorators import SecurityDecorator
from guard_core.models import SecurityConfig


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
        lambda d: d.require_ip(blacklist=["10.0.0.0/33"]),
        "@require_ip blacklist entry '10.0.0.0/33' is not a valid IP address or "
        "CIDR network",
    ),
    (
        lambda d: d.require_ip(whitelist=["203.0.113.7", "not-an-ip"]),
        "@require_ip whitelist entry 'not-an-ip' is not a valid IP address or "
        "CIDR network",
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
        lambda d: d.require_ip(
            whitelist=["203.0.113.7", "10.0.0.0/8", "10.1.2.3/24", "2001:db8::/32"],
            blacklist=["198.51.100.1"],
        ),
    ],
)
def test_valid_values_never_warn(make: Callable[[SecurityDecorator], Any]) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _decorate(_decorator(fail_on_misconfiguration=True), make)
