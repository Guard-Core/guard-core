import logging
from collections.abc import Generator
from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks._strike_forget import forget_category_strikes
from guard_core.sync.core.checks.helpers import _increment_suspicious_counts
from guard_core.sync.handlers import ratelimit_handler
from guard_core.sync.handlers.ratelimit_handler import (
    check_rate_limit_by_ip,
    rate_limit_handler,
)
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.test_sync.conftest import (
    REDIS_URL,
    MockGuardResponse,
    SyncMockGuardRequest,
    suite_redis_prefix,
)

LOGGER = "guard_core.sync.handlers.ratelimit"
PREFIX = "this config object is not the one any guarded app was built with; "
NOTHING = PREFIX + "reset() cleared nothing"
IP = "203.0.113.31"


def _config(**extra: object) -> SyncSecurityConfig:
    values: dict[str, object] = {
        "enable_redis": False,
        "rate_limit": 1,
        "rate_limit_window": 60,
        "enable_rate_limiting": True,
    }
    values.update(extra)
    return SyncSecurityConfig(**values)


@pytest.fixture(autouse=True)
def clean_process_state() -> None:
    ratelimit_handler.clear_by_ip_strikes()
    ratelimit_handler.clear_by_ip_request_windows()
    forget_category_strikes("rate_limit")


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == LOGGER and r.levelno == logging.WARNING
    ]


def _own_window(config: SyncSecurityConfig) -> object:
    def error(status: int, message: str) -> MockGuardResponse:
        return MockGuardResponse(message, status)

    manager = rate_limit_handler(config)
    manager.check_rate_limit(SyncMockGuardRequest(path="/x", client_host=IP), IP, error)
    return manager


def _by_ip_window() -> SyncSecurityConfig:
    config = _config(rate_limit=5)
    check_rate_limit_by_ip(IP, config)
    return config


def _strike() -> MagicMock:
    middleware = MagicMock()
    middleware.config = _config()
    middleware.suspicious_request_counts = {}
    _increment_suspicious_counts(middleware, IP, "rate_limit")
    return middleware


def test_nothing_to_clear_logs_the_old_literal(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger=LOGGER):
        rate_limit_handler(_config()).reset()

    assert _warnings(caplog) == [NOTHING]


@pytest.mark.parametrize(
    ("prepare", "expected"),
    [
        ("own", ["this config object's own request windows"]),
        ("by_ip", ["the by-IP primitive's request windows"]),
        ("strikes", ["the process-wide rate-limit strikes"]),
        (
            "all",
            [
                "this config object's own request windows",
                "the by-IP primitive's request windows",
                "the process-wide rate-limit strikes",
            ],
        ),
    ],
)
def test_something_cleared_logs_the_same_prefix_and_lists_it(
    caplog: pytest.LogCaptureFixture, prepare: str, expected: list[str]
) -> None:
    config = _config()
    keep: list[object] = []
    if prepare in ("own", "all"):
        keep.append(_own_window(config))
    if prepare in ("by_ip", "all"):
        keep.append(_by_ip_window())
    if prepare in ("strikes", "all"):
        keep.append(_strike())

    with caplog.at_level(logging.INFO, logger=LOGGER):
        rate_limit_handler(config).reset()

    assert _warnings(caplog) == [
        PREFIX
        + "no in-process request window of a guarded app was cleared (cleared: "
        + ", ".join(expected)
        + ")"
    ]
    assert keep is not None


def test_the_reset_clears_the_by_ip_windows_between_two_hits() -> None:
    config = _config()
    assert check_rate_limit_by_ip(IP, config) is True
    assert check_rate_limit_by_ip(IP, config) is False

    rate_limit_handler(config).reset()

    assert check_rate_limit_by_ip(IP, config) is True
    assert check_rate_limit_by_ip(IP, config) is False


@pytest.fixture
def redis() -> Generator[RedisManager, None]:
    manager = RedisManager(
        _config(
            enable_redis=True,
            redis_url=REDIS_URL,
            redis_prefix=suite_redis_prefix("wp3fu:report"),
        )
    )
    manager.initialize()
    try:
        yield manager
    finally:
        manager.delete_pattern("*")
        manager.close()


def test_the_reset_clears_the_by_ip_windows_with_redis_too(
    redis: RedisManager,
) -> None:
    config = redis.config
    assert check_rate_limit_by_ip(IP, config, redis) is True
    assert check_rate_limit_by_ip(IP, config, redis) is False

    rate_limit_handler(config).reset()

    assert check_rate_limit_by_ip(IP, config, redis) is True


def test_an_unbound_reset_with_redis_lists_the_redis_clear(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=suite_redis_prefix("wp3fu:report"),
    )

    with caplog.at_level(logging.INFO, logger=LOGGER):
        rate_limit_handler(config).reset()

    assert _warnings(caplog) == [
        PREFIX
        + "no in-process request window of a guarded app was cleared (cleared: "
        + "the Redis rate-limit windows and strikes)"
    ]
