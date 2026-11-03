import logging
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks._shared_strikes import (
    SharedStrikes,
    StrikeReport,
    forget_shared_detection_strikes,
    read_shared_detection_categories,
    record_shared_detection_strikes,
    strike_categories,
)

LOGGER = "guard_core.sync.core.checks.shared_strikes"


def _middleware(redis: object) -> MagicMock:
    middleware = MagicMock()
    middleware.config = SyncSecurityConfig(
        enable_redis=True, enable_ip_banning=True, redis_url="redis://localhost:1"
    )
    middleware.rate_limit_handler.redis_handler = redis
    return middleware


def test_no_category_means_uncategorized_and_a_name_stays_itself() -> None:
    assert tuple(strike_categories([])) == ("uncategorized",)
    assert tuple(strike_categories("xss")) == ("xss",)
    assert tuple(strike_categories(["xss", "sqli"])) == ("xss", "sqli")


def test_the_event_count_adds_the_rate_limit_violations_and_defaults_to_none() -> None:
    assert SharedStrikes({"xss": 2}, 2).rate_limit_violations == 0
    assert SharedStrikes({"xss": 2}, 2).event_count == 2
    assert SharedStrikes({"xss": 2}, 2, 3).event_count == 5


def _count(report: StrikeReport) -> int | None:
    return report.count


def test_a_report_carries_the_count_and_a_landed_ban_reports_zero() -> None:
    report = StrikeReport()
    assert _count(report) is None
    assert report.count_or(lambda: 7) == 7

    report.record(None, False)
    assert _count(report) is None

    report.record(SharedStrikes({"xss": 4}, 4, 1), False)
    assert _count(report) == 5
    assert report.count_or(lambda: 7) == 5

    report.record(SharedStrikes({"xss": 4}, 4, 1), True)
    assert _count(report) == 0


def test_a_failed_record_logs_the_exact_fallback_message(
    caplog: pytest.LogCaptureFixture,
) -> None:
    redis = Mock(record_detection_strikes=MagicMock(side_effect=RuntimeError("down")))

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        shared = record_shared_detection_strikes(
            _middleware(redis), "203.0.113.5", ("xss",), 3600, 10
        )

    assert shared is None
    assert [(r.name, r.getMessage()) for r in caplog.records] == [
        (
            LOGGER,
            "Shared detection strike counter unavailable, counting this detection "
            "strike in this process only: down",
        )
    ]


def test_a_failed_clear_logs_the_exact_message(
    caplog: pytest.LogCaptureFixture,
) -> None:
    redis = Mock(forget_detection_strikes=MagicMock(side_effect=RuntimeError("down")))

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        forget_shared_detection_strikes(_middleware(redis), "203.0.113.5")

    assert [(r.name, r.getMessage()) for r in caplog.records] == [
        (
            LOGGER,
            "Shared detection strike counters of 203.0.113.5 could not be cleared "
            "after the ban, they expire on their own: down",
        )
    ]


def test_a_clear_without_a_shared_redis_handler_has_nothing_to_clear(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        forget_shared_detection_strikes(_middleware(None), "203.0.113.5")

    assert caplog.records == []


def test_a_failed_category_read_logs_the_exact_message(
    caplog: pytest.LogCaptureFixture,
) -> None:
    redis = Mock(read_detection_categories=MagicMock(side_effect=RuntimeError("down")))

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        found = read_shared_detection_categories(redis, "203.0.113.5", 3600)

    assert found is None
    assert [(r.name, r.getMessage()) for r in caplog.records] == [
        (
            LOGGER,
            "Shared detection categories unavailable, using the categories this "
            "process saw: down",
        )
    ]
