import importlib.util
import inspect
import logging
import warnings
from collections.abc import Generator
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest

from guard_core import _staged_defaults as staged
from guard_core.core.initialization._route_limit_report import (
    report_route_limits_with_global_switch_off,
)
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig

RATE_LIMIT_MESSAGE = (
    "rate_limit is not set, so the default of 10 requests per rate_limit_window "
    "(60 s) applies. guard-core 5.0.0 raises the default to 120 requests per 60 s. "
    "Pass rate_limit=10 to SecurityConfig to keep today's limit, or rate_limit=120 "
    "to opt in now. This warning is logged once."
)
PREFIX_MESSAGE = (
    "redis_prefix is the default 'guard_core:' while Redis is enabled: every app on "
    "the same Redis that keeps the default shares its bans and rate-limit counters. "
    "Set a unique redis_prefix per app. This warning is logged once."
)


@pytest.fixture(autouse=True)
def _reset_flags() -> Generator[None, None, None]:
    names = (
        "_rate_limit_default_warned",
        "_default_prefix_warned",
    )
    saved = {name: getattr(staged, name) for name in names}
    for name in names:
        setattr(staged, name, False)
    yield
    for name, value in saved.items():
        setattr(staged, name, value)


def _fresh_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "fresh_staged_defaults", staged.__file__
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _build(**settings: Any) -> list[warnings.WarningMessage]:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        SecurityConfig(**settings)
    return [w for w in caught if issubclass(w.category, DeprecationWarning)]


def test_every_warning_flag_starts_unset_in_a_fresh_process() -> None:
    fresh = _fresh_module()

    assert fresh._rate_limit_default_warned is False
    assert fresh._default_prefix_warned is False
    assert fresh.logger.name == "guard_core.models"
    assert fresh.DEFAULT_REDIS_PREFIX == "guard_core:"


def test_the_warnings_carry_their_exact_text() -> None:
    caught = _build()

    assert [str(w.message) for w in caught] == [RATE_LIMIT_MESSAGE]


def test_the_warnings_point_at_the_line_that_builds_the_config() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        frame = inspect.currentframe()
        assert frame is not None
        line = frame.f_lineno + 1
        SecurityConfig()

    deprecations = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert [(w.filename, w.lineno) for w in deprecations] == [(__file__, line)]


def test_each_warning_is_given_once_per_process() -> None:
    first = _build()
    second = _build()

    assert len(first) == 1
    assert second == []


def test_the_logged_copies_carry_the_same_text(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core.models"):
        _build()

    messages = [r.getMessage() for r in caplog.records]
    assert messages == [RATE_LIMIT_MESSAGE]


def test_the_default_prefix_warning_is_given_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core.models"):
        _build(enable_redis=True, rate_limit=5)
        _build(enable_redis=True, rate_limit=5)

    assert [r.getMessage() for r in caplog.records] == [PREFIX_MESSAGE]


def test_the_route_limit_report_names_the_routes_that_stay_on() -> None:
    config = SecurityConfig(enable_redis=False, enable_rate_limiting=False)
    limited = RouteConfig()
    limited.rate_limit = 3
    geo = RouteConfig()
    geo.geo_rate_limits = {"US": (1, 60)}
    plain = RouteConfig()
    decorator = Mock()
    decorator._route_configs = {"b.route": limited, "a.route": geo, "c.route": plain}
    logger = Mock()

    report_route_limits_with_global_switch_off(config, decorator, logger)

    logger.info.assert_called_once_with(
        "enable_rate_limiting is False, so the global rate limit is off; the "
        "rate limits of these routes stay on: %s",
        "a.route, b.route",
    )
