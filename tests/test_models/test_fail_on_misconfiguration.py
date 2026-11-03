import logging
import warnings
from typing import Any

import pytest

from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.decorators import SecurityDecorator
from guard_core.models import SecurityConfig


def _build(**settings: object) -> SecurityConfig:
    return SecurityConfig(enable_redis=False, **settings)


@pytest.mark.parametrize(
    ("settings", "named_value"),
    [
        ({"rate_limit": 0}, "rate_limit is 0"),
        ({"rate_limit": -5}, "rate_limit is -5"),
        ({"rate_limit_window": 0}, "rate_limit_window is 0"),
        ({"rate_limit_window": -9}, "rate_limit_window is -9"),
        (
            {"endpoint_rate_limits": {"/login": (0, 60)}},
            "endpoint_rate_limits['/login'] is (0, 60)",
        ),
        (
            {"endpoint_rate_limits": {"/login": (5, 0)}},
            "endpoint_rate_limits['/login'] is (5, 0)",
        ),
    ],
)
class TestNonPositiveRateLimit:
    def test_an_unset_flag_refuses_to_start_naming_the_problem_and_the_old_value(
        self, settings: dict[str, Any], named_value: str
    ) -> None:
        with pytest.raises(ValueError) as caught:
            _build(**settings)

        assert named_value in str(caught.value)
        assert "fail_on_misconfiguration=False" in str(caught.value)

    def test_true_raises_with_the_same_problem_text(
        self, settings: dict[str, Any], named_value: str
    ) -> None:
        with pytest.raises(ValueError, match="fail_on_misconfiguration"):
            _build(fail_on_misconfiguration=True, **settings)
        with pytest.raises(ValueError) as caught:
            _build(fail_on_misconfiguration=True, **settings)
        assert named_value in str(caught.value)

    def test_false_logs_one_warning_and_starts(
        self,
        settings: dict[str, Any],
        named_value: str,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="guard_core"):
            with warnings.catch_warnings():
                warnings.simplefilter("error")
                config = _build(fail_on_misconfiguration=False, **settings)

        assert config.fail_on_misconfiguration is False
        messages = [r.getMessage() for r in caplog.records if named_value in r.message]
        assert len(messages) == 1
        assert "fail_on_misconfiguration=False keeps starting" in messages[0]


def test_valid_rate_limits_never_raise_whatever_the_flag() -> None:
    for flag in ({}, {"fail_on_misconfiguration": True}):
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            _build(rate_limit=1, rate_limit_window=1, **flag)


def test_flag_defaults_to_true_when_unset() -> None:
    assert _build().fail_on_misconfiguration is True


def test_an_unset_flag_refuses_a_misconfigured_decorator() -> None:
    decorator = SecurityDecorator(_build())

    def route() -> None:
        pass

    with pytest.raises(ValueError, match="fail_on_misconfiguration=False"):
        decorator.rate_limit(requests=0, window=60)(route)


async def test_an_unset_flag_refuses_an_unreachable_ban_threshold_at_bind() -> None:
    config = _build(auto_ban_threshold=10**9, lazy_init=False)

    with pytest.raises(ValueError, match="fail_on_misconfiguration=False"):
        await HandlerInitializer(config=config).initialize_redis_handlers()


async def test_the_old_value_keeps_starting_at_bind(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _build(
        auto_ban_threshold=10**9, lazy_init=False, fail_on_misconfiguration=False
    )

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        await HandlerInitializer(config=config).initialize_redis_handlers()

    assert any("can never fire" in r.getMessage() for r in caplog.records)
