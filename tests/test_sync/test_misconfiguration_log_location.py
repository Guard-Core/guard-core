import inspect
import logging

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.decorators import SecurityDecorator


def _next_line() -> int:
    frame = inspect.currentframe()
    assert frame is not None and frame.f_back is not None
    return frame.f_back.f_lineno + 1


def _location(caplog: pytest.LogCaptureFixture, marker: str) -> tuple[str, int]:
    [record] = [r for r in caplog.records if marker in r.getMessage()]
    return record.pathname, record.lineno


def test_a_config_misconfiguration_log_names_the_line_that_builds_the_config(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        expected = _next_line()
        SecurityConfig(enable_redis=False, rate_limit=0, fail_on_misconfiguration=False)

    assert _location(caplog, "rate_limit is 0") == (__file__, expected)


def test_a_decorator_misconfiguration_log_names_the_decorated_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    decorator = SecurityDecorator(
        SecurityConfig(enable_redis=False, fail_on_misconfiguration=False)
    )

    def route() -> None:
        pass

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        expected = _next_line()
        decorator.rate_limit(0, 60)(route)

    assert _location(caplog, "@rate_limit(") == (__file__, expected)


def test_a_startup_misconfiguration_log_names_the_bind_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(
        enable_redis=False,
        lazy_init=False,
        auto_ban_threshold=10**9,
        fail_on_misconfiguration=False,
    )
    initializer = HandlerInitializer(config=config)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        expected = _next_line()
        initializer.initialize_redis_handlers()

    assert _location(caplog, "can never fire") == (__file__, expected)
