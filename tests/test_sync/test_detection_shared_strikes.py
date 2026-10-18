import logging
import uuid
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import SecurityConfig, ThreatBanConfig
from guard_core.sync.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.sync.detection_result import DetectionResult
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.test_sync.conftest import REDIS_URL

IP = "198.51.100.77"
THRESHOLD = 5
WORKERS = 4
DETECT_MODULE = "guard_core.sync.core.checks.implementations.suspicious_activity"


def _config(redis: bool = True, **overrides: Any) -> SecurityConfig:
    values: dict[str, Any] = {
        "enable_redis": redis,
        "redis_url": REDIS_URL,
        "redis_prefix": f"test:wp3fu:detect:{uuid.uuid4().hex}:",
        "enable_penetration_detection": True,
        "enable_ip_banning": True,
        "auto_ban_threshold": THRESHOLD,
        "auto_ban_duration": 300,
        "enable_rate_limiting": False,
    }
    values.update(overrides)
    return SecurityConfig(**values)


def _result(*categories: str) -> DetectionResult:
    return DetectionResult(
        is_threat=True,
        trigger_info="probe",
        threat_categories=list(categories),
        threat_scores={category: 1.0 for category in categories},
    )


class _Worker:
    def __init__(
        self,
        config: SecurityConfig,
        redis: RedisManager | None,
        monkeypatch: pytest.MonkeyPatch,
        result: DetectionResult,
    ) -> None:
        self.bans: list[tuple[str, int, str]] = []
        middleware = MagicMock()
        middleware.config = config
        middleware.logger = logging.getLogger("test_detection_shared_strikes")
        middleware.suspicious_request_counts = {}
        middleware.rate_limit_handler.redis_handler = redis
        middleware.event_bus.send_middleware_event = MagicMock()
        middleware.create_error_response = MagicMock(
            return_value=MagicMock(status_code=403)
        )
        middleware.route_resolver.should_bypass_check = lambda *_: False
        self.middleware = middleware
        self.check = SuspiciousActivityCheck(middleware)

        def record_ban(ip: str, duration: int, reason: str = "") -> bool:
            self.bans.append((ip, duration, reason))
            return True

        self.check.ip_ban_manager = Mock(ban_ip=record_ban)
        self.result = result
        self.monkeypatch = monkeypatch

    def detect(self, result: DetectionResult | None = None) -> Any:
        chosen = result or self.result

        def fake_detect(*_args: Any, **_kwargs: Any) -> DetectionResult:
            return chosen

        self.monkeypatch.setattr(
            f"{DETECT_MODULE}.get_cached_detection_result", fake_detect
        )
        request = MagicMock()
        request.state.is_whitelisted = False
        request.state.client_ip = IP
        request.state.route_config = None
        request.url_full = "https://test/x"
        return self.check.check(request)


@pytest.fixture
def redis_workers(
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[list[_Worker], None]:
    config = _config()
    redis = RedisManager(config)
    redis.initialize()
    workers = [
        _Worker(config, redis, monkeypatch, _result("xss")) for _ in range(WORKERS)
    ]
    try:
        yield workers
    finally:
        redis.delete_pattern("*")
        redis.close()


def _all_bans(workers: list[_Worker]) -> list[tuple[str, int, str]]:
    return [ban for worker in workers for ban in worker.bans]


def _strike_until_banned(
    workers: list[_Worker], result: DetectionResult | None = None, limit: int = 60
) -> int:
    strikes = 0
    while not _all_bans(workers) and strikes < limit:
        workers[strikes % len(workers)].detect(result)
        strikes += 1
    return strikes


def test_the_flat_threshold_counts_detections_across_every_worker(
    redis_workers: list[_Worker],
) -> None:
    strikes = _strike_until_banned(redis_workers)

    assert strikes == THRESHOLD
    assert _all_bans(redis_workers) == [(IP, 300, "penetration_attempt")]


def test_the_flat_threshold_totals_the_categories_across_workers(
    redis_workers: list[_Worker],
) -> None:
    categories = ["xss", "sqli"]
    strikes = 0
    while not _all_bans(redis_workers) and strikes < 60:
        worker = redis_workers[strikes % WORKERS]
        worker.detect(_result(categories[strikes % 2]))
        strikes += 1

    assert strikes == THRESHOLD


def test_a_per_category_threshold_counts_across_workers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(
        auto_ban_threshold=1000,
        threat_ban_config={"xss": ThreatBanConfig(threshold=4, duration=900)},
    )
    redis = RedisManager(config)
    redis.initialize()
    workers = [
        _Worker(config, redis, monkeypatch, _result("xss")) for _ in range(WORKERS)
    ]
    try:
        strikes = _strike_until_banned(workers)
        assert strikes == 4
        assert _all_bans(workers) == [(IP, 900, "penetration_attempt:xss")]
    finally:
        redis.delete_pattern("*")
        redis.close()


def test_a_landed_ban_clears_the_shared_detection_counters(
    redis_workers: list[_Worker],
) -> None:
    _strike_until_banned(redis_workers)
    redis = redis_workers[0].middleware.rate_limit_handler.redis_handler
    prefix = redis.config.redis_prefix

    with redis.get_connection() as conn:
        assert conn.keys(f"{prefix}detection:*") == []

    for index in range(THRESHOLD - 1):
        redis_workers[index % WORKERS].detect()
    assert len(_all_bans(redis_workers)) == 1


def test_the_in_process_counts_stay_populated(
    redis_workers: list[_Worker],
) -> None:
    worker = redis_workers[0]
    worker.detect()
    worker.detect()

    assert dict(worker.middleware.suspicious_request_counts[IP]) == {"xss": 2}


def test_a_redis_error_falls_back_to_the_process_count(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    config = _config()
    broken = Mock(
        config=config,
        record_detection_strikes=MagicMock(side_effect=RuntimeError("redis down")),
    )
    worker = _Worker(config, broken, monkeypatch, _result("xss"))

    with caplog.at_level(logging.WARNING):
        for _ in range(THRESHOLD):
            worker.detect()

    assert worker.bans == [(IP, 300, "penetration_attempt")]
    assert any("detection strike" in r.getMessage() for r in caplog.records)


def test_passive_mode_records_nothing_in_redis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(passive_mode=True)
    redis = RedisManager(config)
    redis.initialize()
    worker = _Worker(config, redis, monkeypatch, _result("xss"))
    try:
        for _ in range(THRESHOLD + 2):
            worker.detect()
        with redis.get_connection() as conn:
            assert conn.keys(f"{config.redis_prefix}detection:*") == []
        assert worker.bans == []
    finally:
        redis.delete_pattern("*")
        redis.close()


def test_without_redis_each_process_keeps_its_own_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(redis=False)
    workers = [
        _Worker(config, None, monkeypatch, _result("xss")) for _ in range(WORKERS)
    ]

    for index in range(THRESHOLD * WORKERS - WORKERS):
        workers[index % WORKERS].detect()

    assert _all_bans(workers) == []


def _redis_calls(redis: RedisManager, command: str) -> int:
    with redis.get_connection() as conn:
        stats = conn.info("commandstats")
    entry = stats.get(f"cmdstat_{command}")
    return int(entry["calls"]) if entry else 0


def _all_redis_calls(redis: RedisManager) -> int:
    with redis.get_connection() as conn:
        stats = conn.info("commandstats")
    return sum(
        int(entry["calls"]) for name, entry in stats.items() if name != "cmdstat_info"
    )


def test_a_strike_costs_one_script_call_whatever_the_categories(
    redis_workers: list[_Worker],
) -> None:
    worker = redis_workers[0]
    redis = worker.middleware.rate_limit_handler.redis_handler
    worker.detect(_result("xss"))
    before = _redis_calls(redis, "evalsha")

    worker.detect(_result("xss", "sqli", "cmd_injection"))

    assert _redis_calls(redis, "evalsha") - before == 1


def test_a_benign_request_costs_no_redis_command(
    redis_workers: list[_Worker],
) -> None:
    worker = redis_workers[0]
    redis = worker.middleware.rate_limit_handler.redis_handler
    before = _all_redis_calls(redis)

    benign = DetectionResult(is_threat=False, trigger_info="")
    for _ in range(5):
        assert worker.detect(benign) is None

    assert _all_redis_calls(redis) == before


def test_a_detection_without_categories_counts_as_uncategorized(
    redis_workers: list[_Worker],
) -> None:
    strikes = _strike_until_banned(redis_workers, _result())

    assert strikes == THRESHOLD


def test_hostile_signals_count_across_workers_too(
    redis_workers: list[_Worker],
) -> None:
    from guard_core.sync.core.checks.helpers import count_hostile_signal_and_maybe_ban

    banned = False
    strikes = 0
    while not banned and strikes < 60:
        worker = redis_workers[strikes % WORKERS]
        request = MagicMock()
        request.state.client_ip = IP
        request.state.is_whitelisted = False
        request.url_full = "https://test/x"
        banned = count_hostile_signal_and_maybe_ban(
            worker.check, request, "auth_failure", "bad token"
        )
        strikes += 1

    assert strikes == THRESHOLD


def test_a_failed_clear_after_the_ban_is_logged_and_the_ban_stands(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    config = _config()
    redis = Mock(
        config=config,
        record_detection_strikes=MagicMock(
            return_value=(THRESHOLD, 0, {"xss": THRESHOLD})
        ),
        forget_detection_strikes=MagicMock(side_effect=RuntimeError("redis down")),
    )
    worker = _Worker(config, redis, monkeypatch, _result("xss"))

    with caplog.at_level(logging.WARNING):
        worker.detect()

    assert worker.bans == [(IP, 300, "penetration_attempt")]
    assert any("could not be cleared" in r.getMessage() for r in caplog.records)


def test_passive_mode_never_records_a_shared_strike() -> None:
    from guard_core.sync.core.checks._shared_strikes import (
        record_shared_detection_strikes,
    )

    config = _config(passive_mode=True)
    middleware = MagicMock()
    middleware.config = config
    redis = Mock(record_detection_strikes=MagicMock(return_value=(1, 0, {"xss": 1})))
    middleware.rate_limit_handler.redis_handler = redis

    shared = record_shared_detection_strikes(middleware, IP, ("xss",), 3600, 10)

    assert shared is None
    redis.record_detection_strikes.assert_not_called()
