import logging
import uuid
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.sync.core.initialization._whitelist_strikes import (
    reset_strikes_for_changed_whitelist,
    whitelist_fingerprint,
)
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.detection_result import DetectionResult
from guard_core.sync.handlers import ratelimit_handler
from guard_core.sync.handlers.ipban_handler import IPBanManager
from guard_core.sync.handlers.ratelimit_handler import rate_limit_handler
from guard_core.sync.handlers.redis_handler import RedisManager
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from tests.test_sync.conftest import REDIS_URL
from tests.test_sync.engine_redis_commands import (
    engine_commands_sent,
    engine_redis_url,
    unwatch_engine_commands,
)

DETECT = "guard_core.sync.core.checks.implementations.suspicious_activity"
INSIDE = "198.51.100.10"
OUTSIDE = "203.0.113.10"
LOGGER = "guard_core.sync.core.initialization.whitelist_strikes"


def _config(**overrides: Any) -> SyncSecurityConfig:
    values: dict[str, Any] = {
        "enable_redis": True,
        "redis_url": engine_redis_url(REDIS_URL),
        "redis_prefix": f"test:wp3fu:startup:{uuid.uuid4().hex}:",
        "enable_penetration_detection": True,
        "enable_ip_banning": True,
        "auto_ban_threshold": 100,
        "enable_rate_limiting": False,
    }
    values.update(overrides)
    return SyncSecurityConfig(**values)


@pytest.fixture
def redis() -> Generator[RedisManager, None]:
    config = _config()
    manager = RedisManager(config)
    manager.initialize()
    ratelimit_handler.clear_by_ip_strikes()
    try:
        yield manager
    finally:
        manager.delete_pattern("*")
        manager.close()
        unwatch_engine_commands(config.redis_url)
        ratelimit_handler.clear_by_ip_strikes()


@pytest.fixture
def ban_manager(redis: RedisManager) -> IPBanManager:
    manager = IPBanManager()
    manager.redis_handler = redis
    return manager


def _strike(
    redis: RedisManager, monkeypatch: pytest.MonkeyPatch, *ips: str
) -> MagicMock:
    middleware = MagicMock()
    middleware.config = redis.config
    middleware.logger = logging.getLogger("test_whitelist_startup")
    middleware.suspicious_request_counts = {}
    middleware.rate_limit_handler = rate_limit_handler(redis.config)
    middleware.rate_limit_handler.redis_handler = redis
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(return_value=MagicMock())
    middleware.route_resolver.should_bypass_check = lambda *_: False
    check = SuspiciousActivityCheck(middleware)
    check.ip_ban_manager = Mock(_ban_ip_escalating=MagicMock(return_value=True))
    result = DetectionResult(
        is_threat=True,
        trigger_info="probe",
        threat_categories=["xss"],
        threat_scores={"xss": 1.0},
    )

    def fake(*_args: Any, **_kwargs: Any) -> DetectionResult:
        return result

    monkeypatch.setattr(f"{DETECT}.get_cached_detection_result", fake)
    for ip in ips:
        request = MagicMock()
        request.state.is_whitelisted = False
        request.state.client_ip = ip
        request.state.route_config = None
        request.url_full = "https://test/x"
        check.check(request)
    return middleware


def _keys(redis: RedisManager, pattern: str) -> list[str]:
    with redis.get_connection() as conn:
        return sorted(conn.keys(f"{redis.config.redis_prefix}{pattern}"))


def _scans(redis: RedisManager) -> int:
    return engine_commands_sent(redis.config.redis_url, "scan")


def test_the_fingerprint_is_canonical_deduplicated_and_sorted() -> None:
    assert whitelist_fingerprint(["10.0.0.5"]) == whitelist_fingerprint(["10.0.0.5/32"])
    assert whitelist_fingerprint(["10.0.0.5", "10.0.0.5/32"]) == whitelist_fingerprint(
        ["10.0.0.5"]
    )
    assert whitelist_fingerprint(["2001:db8::/32", "10.0.0.0/8"]) == (
        whitelist_fingerprint(["10.0.0.0/8", "2001:db8::/32"])
    )
    assert whitelist_fingerprint(["10.0.0.0/8"]) != whitelist_fingerprint(
        ["10.0.0.0/9"]
    )
    assert len(whitelist_fingerprint([])) == 32


@pytest.mark.parametrize(
    "entry", ["198.51.100.0/24", "198.51.100.10", "198.51.100.10/32"]
)
def test_a_new_startup_whitelist_resets_what_it_covers(
    redis: RedisManager,
    ban_manager: IPBanManager,
    monkeypatch: pytest.MonkeyPatch,
    entry: str,
) -> None:
    middleware = _strike(redis, monkeypatch, INSIDE, OUTSIDE)
    config = _config(redis_prefix=redis.config.redis_prefix, whitelist=[entry])

    reset_strikes_for_changed_whitelist(config, redis, ban_manager)

    assert INSIDE not in middleware.suspicious_request_counts
    assert OUTSIDE in middleware.suspicious_request_counts
    assert _keys(redis, f"detection:strikes:{INSIDE}*") == []
    assert _keys(redis, f"detection:strikes:{OUTSIDE}|*")


def test_two_workers_with_the_same_new_whitelist_run_one_scan(
    redis: RedisManager, ban_manager: IPBanManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    _strike(redis, monkeypatch, INSIDE)
    config = _config(
        redis_prefix=redis.config.redis_prefix, whitelist=["198.51.100.0/24"]
    )
    before = _scans(redis)

    reset_strikes_for_changed_whitelist(config, redis, ban_manager)
    one_run = _scans(redis) - before
    reset_strikes_for_changed_whitelist(config, redis, ban_manager)

    assert one_run == 5
    assert _scans(redis) - before == 5


def test_a_worker_that_finds_the_lock_taken_scans_nothing(
    redis: RedisManager, ban_manager: IPBanManager
) -> None:
    prefix = redis.config.redis_prefix
    config = _config(redis_prefix=prefix, whitelist=["198.51.100.0/24"])
    assert redis.set_key_if_absent("whitelist", "strikes_lock", "1", 60)
    before = _scans(redis)

    reset_strikes_for_changed_whitelist(config, redis, ban_manager)

    assert _scans(redis) == before
    assert _keys(redis, "whitelist:strikes_applied") == []


def test_the_sequence_w2_w1_w2_rescans_on_the_second_w2(
    redis: RedisManager, ban_manager: IPBanManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix = redis.config.redis_prefix
    w2 = _config(redis_prefix=prefix, whitelist=["198.51.100.0/24"])
    w1 = _config(redis_prefix=prefix, whitelist=["203.0.113.0/24"])
    reset_strikes_for_changed_whitelist(w2, redis, ban_manager)
    with redis.get_connection() as conn:
        conn.delete(f"{prefix}whitelist:strikes_lock")
    reset_strikes_for_changed_whitelist(w1, redis, ban_manager)
    with redis.get_connection() as conn:
        conn.delete(f"{prefix}whitelist:strikes_lock")
    middleware = _strike(redis, monkeypatch, INSIDE)

    reset_strikes_for_changed_whitelist(w2, redis, ban_manager)

    assert INSIDE not in middleware.suspicious_request_counts
    assert _keys(redis, f"detection:strikes:{INSIDE}*") == []


def test_a_scan_that_raises_leaves_the_old_fingerprint_and_is_retried(
    redis: RedisManager,
    ban_manager: IPBanManager,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    prefix = redis.config.redis_prefix
    config = _config(redis_prefix=prefix, whitelist=["198.51.100.0/24"])
    _strike(redis, monkeypatch, INSIDE)
    real = ban_manager.forget_strikes_inside

    def boom(entries: Any, strict: bool = False) -> None:
        raise RuntimeError("scan died")

    monkeypatch.setattr(ban_manager, "forget_strikes_inside", boom)
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        reset_strikes_for_changed_whitelist(config, redis, ban_manager)

    assert _keys(redis, "whitelist:strikes_applied") == []
    assert [(r.name, r.getMessage()) for r in caplog.records if r.name == LOGGER] == [
        (
            LOGGER,
            "The strikes of the startup whitelist could not be reset, the next "
            "start tries again: scan died",
        )
    ]
    monkeypatch.setattr(ban_manager, "forget_strikes_inside", real)
    with redis.get_connection() as conn:
        conn.delete(f"{prefix}whitelist:strikes_lock")

    reset_strikes_for_changed_whitelist(config, redis, ban_manager)

    assert _keys(redis, "whitelist:strikes_applied")
    assert _keys(redis, f"detection:strikes:{INSIDE}*") == []


def test_a_redis_error_while_reading_the_fingerprint_does_not_stop_the_start(
    caplog: pytest.LogCaptureFixture,
) -> None:
    redis = Mock(get_key=MagicMock(side_effect=RuntimeError("down")))

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        reset_strikes_for_changed_whitelist(
            _config(whitelist=["10.0.0.0/8"]), redis, Mock()
        )

    assert any("could not be reset" in r.getMessage() for r in caplog.records)


def test_an_empty_whitelist_stores_its_fingerprint_with_only_the_carve_scan(
    redis: RedisManager, ban_manager: IPBanManager
) -> None:
    config = _config(redis_prefix=redis.config.redis_prefix)
    before = _scans(redis)

    reset_strikes_for_changed_whitelist(config, redis, ban_manager)

    assert _keys(redis, "whitelist:strikes_applied")
    assert _scans(redis) - before == 1


def test_a_disabled_redis_takes_no_lock() -> None:
    manager = RedisManager(SyncSecurityConfig(enable_redis=False))

    assert manager.set_key_if_absent("ns", "key", "1", 5) is False


def test_the_initializer_runs_the_reset_once_redis_is_connected(
    redis: RedisManager, ban_manager: IPBanManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    middleware = _strike(redis, monkeypatch, INSIDE, OUTSIDE)
    config = _config(
        redis_prefix=redis.config.redis_prefix, whitelist=["198.51.100.0/24"]
    )
    initializer = HandlerInitializer(config, redis_handler=redis)

    try:
        initializer.initialize_redis_handlers()
    finally:
        sus_patterns_handler.redis_handler = None

    assert INSIDE not in middleware.suspicious_request_counts
    assert OUTSIDE in middleware.suspicious_request_counts


def test_two_different_whitelists_within_the_lock_window_both_reset(
    redis: RedisManager, ban_manager: IPBanManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix = redis.config.redis_prefix
    first = _config(redis_prefix=prefix, whitelist=["203.0.113.0/24"])
    second = _config(redis_prefix=prefix, whitelist=["198.51.100.0/24"])
    reset_strikes_for_changed_whitelist(first, redis, ban_manager)
    middleware = _strike(redis, monkeypatch, INSIDE)

    reset_strikes_for_changed_whitelist(second, redis, ban_manager)

    assert INSIDE not in middleware.suspicious_request_counts
    assert _keys(redis, "whitelist:strikes_lock") == []


def test_a_failed_range_scan_inside_the_ban_manager_keeps_the_old_fingerprint(
    redis: RedisManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = IPBanManager()
    manager.redis_handler = Mock(
        config=redis.config, get_connection=Mock(side_effect=RuntimeError("scan died"))
    )
    config = _config(
        redis_prefix=redis.config.redis_prefix, whitelist=["198.51.100.0/24"]
    )

    reset_strikes_for_changed_whitelist(config, redis, manager)

    assert _keys(redis, "whitelist:strikes_applied") == []
    assert _keys(redis, "whitelist:strikes_lock") == []


def test_a_failed_per_ip_forget_keeps_the_old_fingerprint(
    redis: RedisManager,
) -> None:
    manager = IPBanManager()
    manager.redis_handler = Mock(
        config=redis.config,
        delete=MagicMock(side_effect=RuntimeError("redis down")),
        forget_detection_strikes=MagicMock(),
    )
    config = _config(redis_prefix=redis.config.redis_prefix, whitelist=[INSIDE])

    reset_strikes_for_changed_whitelist(config, redis, manager)

    assert _keys(redis, "whitelist:strikes_applied") == []


def test_the_unban_and_range_calls_keep_their_warning_without_strict(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = IPBanManager()
    manager.redis_handler = Mock(
        config=SyncSecurityConfig(enable_redis=False),
        get_connection=Mock(side_effect=RuntimeError("down")),
        delete=MagicMock(side_effect=RuntimeError("down")),
        forget_detection_strikes=MagicMock(),
    )

    with caplog.at_level(logging.WARNING):
        manager.forget_strikes_inside(["198.51.100.0/24"])
        manager.forget_strikes_of_ip(INSIDE)

    assert (
        len(
            [
                r
                for r in caplog.records
                if "could not be cleared" in r.getMessage()
                or "inside a range" in r.getMessage()
            ]
        )
        == 2
    )


def test_the_initializer_skips_the_reset_when_redis_never_connected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(whitelist=["198.51.100.0/24"])
    manager = RedisManager(config)
    spy = MagicMock()
    monkeypatch.setattr(
        "guard_core.sync.core.initialization._whitelist_strikes."
        "reset_strikes_for_changed_whitelist",
        spy,
    )
    monkeypatch.setattr(
        "guard_core.sync.core.initialization._whitelist_strikes.is_connected_redis_manager",
        lambda _handler: False,
    )
    initializer = HandlerInitializer(config, redis_handler=manager)
    monkeypatch.setattr(initializer, "_initialize_cloud_and_geo_redis", MagicMock())

    try:
        initializer._initialize_connected_redis_handlers()
    finally:
        sus_patterns_handler.redis_handler = None
        IPBanManager().redis_handler = None
        manager.close()

    spy.assert_not_called()


def test_the_connected_predicate_needs_a_real_connected_manager(
    redis: RedisManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    from guard_core.sync.core.initialization._whitelist_strikes import (
        is_connected_redis_manager,
    )

    assert is_connected_redis_manager(redis) is True
    assert is_connected_redis_manager(Mock(_redis=object())) is False
    monkeypatch.setattr(redis, "_redis", None)
    assert is_connected_redis_manager(redis) is False
    assert is_connected_redis_manager(None) is False
