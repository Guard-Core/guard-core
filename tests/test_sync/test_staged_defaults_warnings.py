import logging
from collections.abc import Generator

import pytest

from guard_core import _staged_defaults as validators
from guard_core.models import SyncSecurityConfig


@pytest.fixture(autouse=True)
def _reset_staged_default_warnings() -> Generator[None, None, None]:
    names = ("_default_prefix_warned",)
    saved = {name: getattr(validators, name, True) for name in names}
    for name in names:
        setattr(validators, name, False)
    yield
    for name, value in saved.items():
        setattr(validators, name, value)


def test_the_limit_defaults_are_what_5_0_0_ships() -> None:
    config = SyncSecurityConfig()

    assert config.rate_limit == 120
    assert config.rate_limit_window == 60
    assert config.enable_rate_limiting is True


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
        SyncSecurityConfig(enable_redis=True, rate_limit=5)
        SyncSecurityConfig(enable_redis=True, rate_limit=5)

    assert len(_prefix_warnings(caplog)) == 1
    assert "guard_core:" in _prefix_warnings(caplog)[0]


def test_a_custom_prefix_or_no_redis_is_silent(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core.models"):
        SyncSecurityConfig(enable_redis=True, redis_prefix="myapp:", rate_limit=5)
        SyncSecurityConfig(enable_redis=False, rate_limit=5)

    assert _prefix_warnings(caplog) == []
