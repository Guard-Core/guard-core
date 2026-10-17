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
        lambda d: d.rate_limit(0, 60),
        "@rate_limit(requests=0, window=60): the limit and the window must both "
        "be at least 1",
    ),
    (
        lambda d: d.rate_limit(5, 0),
        "@rate_limit(requests=5, window=0): the limit and the window must both "
        "be at least 1",
    ),
    (
        lambda d: d.rate_limit(5, -3),
        "@rate_limit(requests=5, window=-3)",
    ),
    (
        lambda d: d.geo_rate_limit({"US": (0, 60)}),
        "@geo_rate_limit entry 'US' is (0, 60): the limit and the window must "
        "both be at least 1",
    ),
    (
        lambda d: d.geo_rate_limit({"*": (5, 0)}),
        "@geo_rate_limit entry '*' is (5, 0)",
    ),
]


@pytest.mark.parametrize(("make", "problem"), BAD_VALUES)
class TestBadRouteArgument:
    def test_unset_flag_warns_naming_the_value(
        self, make: Callable[[SecurityDecorator], Any], problem: str
    ) -> None:
        with pytest.warns(DeprecationWarning) as caught:
            _decorate(_decorator(), make)

        message = str(caught[0].message)
        assert problem in message
        assert "fail_on_misconfiguration is not set" in message

    def test_true_raises_and_leaves_no_route_config(
        self, make: Callable[[SecurityDecorator], Any], problem: str
    ) -> None:
        decorator = _decorator(fail_on_misconfiguration=True)

        with pytest.raises(ValueError) as caught:
            _decorate(decorator, make)

        assert problem in str(caught.value)
        assert decorator._route_configs == {}

    def test_false_warns_without_the_not_set_part(
        self, make: Callable[[SecurityDecorator], Any], problem: str
    ) -> None:
        with pytest.warns(DeprecationWarning, match="keeps starting") as caught:
            _decorate(_decorator(fail_on_misconfiguration=False), make)

        assert "is not set" not in str(caught[0].message)


@pytest.mark.parametrize(
    "make",
    [
        lambda d: d.rate_limit(1, 1),
        lambda d: d.geo_rate_limit({"US": (5, 60), "*": (1, 1)}),
    ],
)
def test_valid_values_never_warn(make: Callable[[SecurityDecorator], Any]) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _decorate(_decorator(fail_on_misconfiguration=True), make)
