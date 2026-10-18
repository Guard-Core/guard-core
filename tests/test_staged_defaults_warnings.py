import logging
import warnings
from collections.abc import Generator
from typing import Any

import pytest

from guard_core import _staged_defaults as validators
from guard_core.models import SecurityConfig


@pytest.fixture(autouse=True)
def _reset_staged_default_warnings() -> Generator[None, None, None]:
    names = (
        "_redis_default_warned",
        "_rate_limit_default_warned",
        "_default_prefix_warned",
    )
    saved = {name: getattr(validators, name, True) for name in names}
    for name in names:
        setattr(validators, name, False)
    yield
    for name, value in saved.items():
        setattr(validators, name, value)


def _deprecations(**settings: Any) -> list[str]:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        SecurityConfig(**settings)
    return [
        str(w.message) for w in caught if issubclass(w.category, DeprecationWarning)
    ]


def test_the_defaults_stay_what_4_4_0_shipped() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        config = SecurityConfig()

    assert config.enable_redis is True
    assert config.rate_limit == 10
    assert config.rate_limit_window == 60
    assert config.enable_rate_limiting is True


def test_an_unset_enable_redis_warns_what_5_0_0_changes_and_how_to_opt_in() -> None:
    messages = [m for m in _deprecations(rate_limit=5) if "enable_redis" in m]

    assert len(messages) == 1
    assert "5.0.0" in messages[0]
    assert "enable_redis=False" in messages[0]
    assert "enable_redis=True" in messages[0]


@pytest.mark.parametrize("value", [True, False])
def test_an_explicit_enable_redis_does_not_warn(value: bool) -> None:
    messages = [
        m
        for m in _deprecations(enable_redis=value, rate_limit=5)
        if "enable_redis" in m
    ]

    assert messages == []


def test_the_redis_warning_is_given_once_per_process() -> None:
    first = [m for m in _deprecations(rate_limit=5) if "enable_redis" in m]
    second = [m for m in _deprecations(rate_limit=5) if "enable_redis" in m]

    assert len(first) == 1
    assert second == []


def test_an_unset_rate_limit_warns_that_5_0_0_changes_it_to_120() -> None:
    messages = [m for m in _deprecations(enable_redis=False) if "rate_limit" in m]

    assert len(messages) == 1
    assert "5.0.0" in messages[0]
    assert "10" in messages[0]
    assert "120" in messages[0]
    assert "rate_limit=10" in messages[0]
    assert "rate_limit=120" in messages[0]


@pytest.mark.parametrize(
    "settings",
    [{"rate_limit": 10}, {"rate_limit": 120}, {"enable_rate_limiting": False}],
)
def test_a_stated_limit_or_a_disabled_limiter_does_not_warn(
    settings: dict[str, Any],
) -> None:
    messages = [
        m
        for m in _deprecations(enable_redis=False, **settings)
        if "5.0.0" in m and "rate_limit" in m
    ]

    assert messages == []


def _prefix_warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        record.getMessage()
        for record in caplog.records
        if "redis_prefix" in record.getMessage()
    ]


def test_the_default_redis_prefix_warns_once_when_redis_is_enabled(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core.models"):
        SecurityConfig(enable_redis=True, rate_limit=5)
        SecurityConfig(enable_redis=True, rate_limit=5)

    assert len(_prefix_warnings(caplog)) == 1
    assert "guard_core:" in _prefix_warnings(caplog)[0]


def test_a_custom_prefix_or_no_redis_is_silent(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core.models"):
        SecurityConfig(enable_redis=True, redis_prefix="myapp:", rate_limit=5)
        SecurityConfig(enable_redis=False, rate_limit=5)

    assert _prefix_warnings(caplog) == []
