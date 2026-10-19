import logging
import warnings

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer

MARKER = "whitelist_access_only is not set"


@pytest.fixture(autouse=True)
def warn_again(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "guard_core._staged_defaults._whitelist_access_only_warned", False
    )


def _bind_twice(
    config: SecurityConfig, caplog: pytest.LogCaptureFixture
) -> tuple[int, int]:
    with (
        caplog.at_level(logging.WARNING, logger="guard_core"),
        warnings.catch_warnings(record=True) as caught,
    ):
        warnings.simplefilter("always")
        HandlerInitializer(config=config).initialize_redis_handlers()
        HandlerInitializer(config=config).initialize_redis_handlers()
    logged = sum(MARKER in message for message in caplog.messages)
    return logged, sum(MARKER in str(item.message) for item in caught)


def test_a_whitelist_set_after_construction_warns_once_across_two_binds(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(enable_redis=False, lazy_init=False)
    config.whitelist = ("198.51.100.0/24",)

    assert _bind_twice(config, caplog) == (1, 1)


def test_an_explicit_flag_never_warns_at_bind(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(
        enable_redis=False, lazy_init=False, whitelist_access_only=False
    )
    config.whitelist = ("198.51.100.0/24",)

    assert _bind_twice(config, caplog) == (0, 0)


def test_no_whitelist_never_warns_at_bind(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(enable_redis=False, lazy_init=False)

    assert _bind_twice(config, caplog) == (0, 0)
