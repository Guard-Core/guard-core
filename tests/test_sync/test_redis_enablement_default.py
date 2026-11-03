import logging

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.handlers import ratelimit_handler
from guard_core.sync.handlers.ratelimit_handler import RateLimitManager
from guard_core.sync.handlers.redis_handler import RedisManager

CONNECTION_FIELDS = {
    "redis_url": "redis://localhost:6379",
    "redis_prefix": "app:",
    "redis_socket_connect_timeout": 1.5,
    "redis_socket_timeout": 1.5,
    "redis_health_check_interval": 10,
    "redis_max_connections": 20,
    "redis_pool_timeout": 0.5,
    "redis_retries": 2,
    "redis_fail_open": True,
}


def _config(**settings: object) -> SyncSecurityConfig:
    return SyncSecurityConfig(rate_limit=100, **settings)


def test_the_field_stays_unset_and_resolves_off_without_a_connection_field() -> None:
    config = _config()

    assert config.enable_redis is False
    assert "enable_redis" not in config.model_fields_set


@pytest.mark.parametrize(("field", "value"), CONNECTION_FIELDS.items())
def test_an_explicit_connection_field_turns_redis_on_and_names_itself(
    field: str, value: object
) -> None:
    config = _config(**{field: value})

    assert config.enable_redis is True
    assert "enable_redis" not in config.model_fields_set


@pytest.mark.parametrize("flag", [True, False])
def test_an_explicit_flag_always_wins(flag: bool) -> None:
    assert _config(enable_redis=flag).enable_redis is flag
    assert _config(enable_redis=flag, redis_prefix="app:").enable_redis is flag


@pytest.mark.parametrize(("field", "value"), CONNECTION_FIELDS.items())
def test_a_field_assigned_after_construction_joins_the_rule(
    field: str, value: object
) -> None:
    config = _config()
    before = config.enable_redis

    setattr(config, field, value)

    assert before is False
    assert config.enable_redis is True
    assert "enable_redis" not in config.model_fields_set


def test_an_explicit_flag_is_not_re_resolved_by_a_later_assignment() -> None:
    config = _config(enable_redis=False)

    config.redis_prefix = "app:"

    assert config.enable_redis is False


def test_a_copy_with_a_connection_field_resolves_again() -> None:
    config = _config()

    copied = config.model_copy(update={"redis_prefix": "app:"})

    assert copied.enable_redis is True
    assert config.enable_redis is False


@pytest.mark.parametrize("url", ["", None])
def test_a_falsy_redis_url_never_connects(
    url: str | None, caplog: pytest.LogCaptureFixture
) -> None:
    config = _config(enable_redis=True, redis_url=url)

    with caplog.at_level(logging.WARNING):
        manager = RedisManager(config)
        manager.initialize()

    assert manager._redis is None
    assert [r.getMessage() for r in caplog.records] == [
        "Redis URL is None, skipping connection"
    ]


def test_a_disabled_redis_with_a_falsy_url_says_nothing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(enable_redis=False, redis_url="")

    with caplog.at_level(logging.WARNING):
        manager = RedisManager(config)
        manager.initialize()

    assert manager._redis is None
    assert caplog.records == []


@pytest.mark.parametrize("url", ["", None])
def test_a_falsy_redis_url_never_builds_a_client_to_reset_rate_limits(
    url: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    cleared: list[tuple[str, str]] = []

    def fake_clear(address: str, pattern: str) -> int:
        cleared.append((address, pattern))
        return 0

    monkeypatch.setattr(ratelimit_handler, "scan_unlink_through_new_client", fake_clear)

    RateLimitManager(_config(enable_redis=True, redis_url=url)).reset()

    assert cleared == []


def test_the_bind_resolves_a_flag_that_construction_never_saw() -> None:
    config = SyncSecurityConfig.model_construct(redis_prefix="app:", lazy_init=False)
    before = config.enable_redis

    HandlerInitializer(config=config).initialize_redis_handlers()

    assert before is False
    assert config.enable_redis is True
    assert "enable_redis" not in config.model_fields_set
