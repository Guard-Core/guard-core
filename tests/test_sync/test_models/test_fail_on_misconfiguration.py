import logging
import warnings
from typing import Any

import pytest

from guard_core.models import SecurityConfig


def _build(**settings: Any) -> SecurityConfig:
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
    def test_unset_flag_warns_naming_the_field_the_value_and_the_opt_in(
        self,
        settings: dict[str, Any],
        named_value: str,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="guard_core"):
            with pytest.warns(DeprecationWarning) as caught:
                _build(**settings)

        message = str(caught[0].message)
        assert named_value in message
        assert "fail_on_misconfiguration is not set" in message
        assert "guard-core 5.0.0 will refuse to start" in message
        assert "fail_on_misconfiguration=True" in message
        assert any(named_value in record.getMessage() for record in caplog.records)

    def test_true_raises_with_the_same_problem_text(
        self, settings: dict[str, Any], named_value: str
    ) -> None:
        with pytest.raises(ValueError, match="fail_on_misconfiguration"):
            _build(fail_on_misconfiguration=True, **settings)
        with pytest.raises(ValueError) as caught:
            _build(fail_on_misconfiguration=True, **settings)
        assert named_value in str(caught.value)

    def test_false_warns_without_the_not_set_part(
        self, settings: dict[str, Any], named_value: str
    ) -> None:
        with pytest.warns(DeprecationWarning) as caught:
            _build(fail_on_misconfiguration=False, **settings)

        message = str(caught[0].message)
        assert named_value in message
        assert "is not set" not in message
        assert "fail_on_misconfiguration=False keeps starting" in message


def test_valid_rate_limits_never_warn_whatever_the_flag() -> None:
    for flag in ({}, {"fail_on_misconfiguration": True}):
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            _build(rate_limit=1, rate_limit_window=1, **flag)


def test_flag_defaults_to_false_when_unset() -> None:
    with pytest.warns(DeprecationWarning):
        config = _build(rate_limit=0)
    assert config.fail_on_misconfiguration is False
