import gc
import logging
import time
import uuid
from collections.abc import AsyncGenerator
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest

from guard_core._security_config_batch import apply_config_batch
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.handlers import ratelimit_handler
from guard_core.handlers.ratelimit_handler import (
    RateLimitManager,
    RateLimitTier,
    rate_limit_handler,
    record_shared_violation,
)
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL, MockGuardRequest, MockGuardResponse


@pytest.fixture(autouse=True)
def clean_rate_limit_process_state() -> None:
    from guard_core.core.checks._strike_forget import forget_category_strikes

    ratelimit_handler.clear_by_ip_strikes()
    ratelimit_handler.clear_by_ip_request_windows()
    forget_category_strikes("rate_limit")


UNBOUND_RESET_WARNING = (
    "this config object is not the one any guarded app was built with; "
    "reset() cleared nothing"
)


def _config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=True,
        rate_limit=2,
        rate_limit_window=60,
    )


def _guarded_app(config: SecurityConfig) -> RateLimitManager:
    manager = RateLimitManager(config)
    HandlerInitializer(config, rate_limit_handler=manager)
    return manager


async def _error_response(status_code: int, message: str) -> MockGuardResponse:
    return MockGuardResponse(message, status_code)


async def _request_status(manager: RateLimitManager) -> int:
    request = MockGuardRequest(path="/x", client_host="203.0.113.9")
    response = await manager.check_rate_limit(request, "203.0.113.9", _error_response)
    return 200 if response is None else response.status_code


async def _exhaust(manager: RateLimitManager) -> None:
    assert await _request_status(manager) == 200
    assert await _request_status(manager) == 200
    assert await _request_status(manager) == 429


async def test_the_documented_reset_reaches_the_app_limiter() -> None:
    config = _config()
    app = _guarded_app(config)
    await _exhaust(app)

    await rate_limit_handler(config).reset()

    assert await _request_status(app) == 200


async def test_the_documented_reset_works_when_the_user_asks_first() -> None:
    config = _config()
    user_side = rate_limit_handler(config)
    app = _guarded_app(config)
    await _exhaust(app)

    await user_side.reset()

    assert await _request_status(app) == 200


async def test_managers_built_from_one_config_object_are_one_manager() -> None:
    config = _config()

    assert RateLimitManager(config) is RateLimitManager(config)
    assert rate_limit_handler(config) is RateLimitManager(config)


async def test_equal_but_distinct_configs_give_two_managers() -> None:
    first, second = _config(), _config()
    assert first == second

    assert RateLimitManager(first) is not RateLimitManager(second)


async def test_the_handlers_and_the_script_are_shared_through_the_one_manager() -> None:
    config = _config()
    first = RateLimitManager(config)
    redis, agent = Mock(), Mock()

    await first.initialize_redis(redis)
    await first.initialize_agent(agent)
    first.rate_limit_script_sha = "sha"

    second = RateLimitManager(config)
    assert (second.redis_handler, second.agent_handler) == (redis, agent)
    assert second.rate_limit_script_sha == "sha"


async def test_resetting_one_app_leaves_the_app_of_another_config_blocked() -> None:
    first_config, second_config = _config(), _config()
    first, second = _guarded_app(first_config), _guarded_app(second_config)
    await _exhaust(first)
    await _exhaust(second)

    await rate_limit_handler(first_config).reset()

    assert await _request_status(first) == 200
    assert await _request_status(second) == 429


async def test_equal_but_distinct_configs_stay_isolated() -> None:
    first_config, second_config = _config(), _config()
    assert first_config == second_config
    assert first_config is not second_config
    first, second = _guarded_app(first_config), _guarded_app(second_config)
    await _exhaust(first)

    assert await _request_status(second) == 200


async def test_a_model_copy_gets_its_own_state() -> None:
    config = _config()
    app = _guarded_app(config)
    await _exhaust(app)
    copied = config.model_copy(update={"rate_limit": 5})

    assert await _request_status(RateLimitManager(copied)) == 200
    await rate_limit_handler(copied).reset()
    assert await _request_status(app) == 429


async def test_a_dynamic_rule_update_keeps_the_state() -> None:
    config = _config()
    app = _guarded_app(config)
    await _exhaust(app)

    apply_config_batch(config, {"rate_limit": 2})

    assert await _request_status(app) == 429
    await rate_limit_handler(config).reset()
    assert await _request_status(app) == 200


def test_the_entry_goes_when_the_last_holder_drops_the_manager() -> None:
    config = _config()
    manager = RateLimitManager(config)
    key = (RateLimitManager, id(config))
    assert ratelimit_handler._managers[key] is manager

    del manager
    gc.collect()

    assert key not in ratelimit_handler._managers
    assert RateLimitManager(config).config is config


def test_a_live_entry_pins_its_config_so_an_id_is_never_reused() -> None:
    config = _config()
    manager = RateLimitManager(config)
    key = (RateLimitManager, id(config))

    del config
    gc.collect()

    assert ratelimit_handler._managers[key] is manager
    assert id(manager.config) == key[1]


async def test_building_a_manager_again_keeps_handlers_windows_and_script() -> None:
    config = _config()
    first = RateLimitManager(config)
    redis, agent = Mock(), Mock()
    await first.initialize_redis(redis)
    await first.initialize_agent(agent)
    first.rate_limit_script_sha = "sha"
    windows = first.request_timestamps
    assert await _request_status(first) == 200

    again = rate_limit_handler(config)

    assert again is first
    assert (again.redis_handler, again.agent_handler) == (redis, agent)
    assert again.rate_limit_script_sha == "sha"
    assert again.request_timestamps is windows
    assert sum(len(hits) for hits in windows.values()) == 1


class _SubManager(RateLimitManager):
    pass


async def test_a_subclass_gets_its_own_manager_for_the_same_config() -> None:
    config = _config()

    assert _SubManager(config) is not RateLimitManager(config)
    assert _SubManager(config) is _SubManager(config)


async def test_a_new_config_never_inherits_the_state_of_a_dead_one() -> None:
    for _ in range(50):
        config = _config()
        manager = RateLimitManager(config)
        assert not manager.request_timestamps
        await _request_status(manager)
        del config, manager
        gc.collect()


async def test_resetting_a_config_no_app_was_built_with_warns_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config()

    with caplog.at_level(logging.WARNING, logger="guard_core.handlers.ratelimit"):
        await rate_limit_handler(config).reset()

    warnings = [r for r in caplog.records if UNBOUND_RESET_WARNING in r.getMessage()]
    assert len(warnings) == 1


async def test_resetting_the_config_of_a_guarded_app_does_not_warn(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config()
    app = _guarded_app(config)

    with caplog.at_level(logging.WARNING, logger="guard_core.handlers.ratelimit"):
        await rate_limit_handler(config).reset()

    assert not [r for r in caplog.records if UNBOUND_RESET_WARNING in r.getMessage()]
    assert app.bound_to_app


async def test_the_initializer_ignores_a_limiter_that_cannot_be_bound() -> None:
    HandlerInitializer(_config(), rate_limit_handler=object())


async def test_reset_still_clears_the_shared_redis_keys() -> None:
    config = SecurityConfig(
        enable_redis=True,
        enable_penetration_detection=False,
        rate_limit=2,
    )
    manager = _guarded_app(config)
    redis: Any = Mock(delete_pattern=AsyncMock())
    await manager.initialize_redis(redis)

    await rate_limit_handler(config).reset()

    redis.delete_pattern.assert_any_call("rate_limit:rate:*")


@pytest.mark.parametrize(
    "name",
    ["request_timestamps", "redis_handler", "agent_handler", "rate_limit_script_sha"],
)
async def test_a_class_level_assignment_changes_no_manager(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    existing = RateLimitManager(_config())
    before = getattr(existing, name)

    monkeypatch.setattr(RateLimitManager, name, "class-level", raising=False)

    assert getattr(existing, name) is before
    assert getattr(RateLimitManager(_config()), name) != "class-level"


async def _redis_commands_issued(redis: RedisManager) -> int:
    async with redis.get_connection() as conn:
        stats = await conn.info("commandstats")
    return sum(int(entry["calls"]) for entry in stats.values())


@pytest.fixture
async def redis_app() -> AsyncGenerator[tuple[SecurityConfig, RateLimitManager], None]:
    config = SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=f"test:wp3fu:{uuid.uuid4().hex}:",
        enable_penetration_detection=False,
        enable_rate_limiting=True,
        rate_limit=2,
        rate_limit_window=60,
    )
    redis = RedisManager(config)
    await redis.initialize()
    app = _guarded_app(config)
    await app.initialize_redis(redis)
    try:
        yield config, app
    finally:
        await redis.delete_pattern("*")
        await redis.close()


async def test_after_the_documented_reset_the_app_still_counts_through_redis(
    redis_app: tuple[SecurityConfig, RateLimitManager],
) -> None:
    config, app = redis_app
    redis = app.redis_handler
    await _exhaust(app)

    await rate_limit_handler(config).reset()
    before = await _redis_commands_issued(redis)
    assert await _request_status(app) == 200

    assert app.redis_handler is redis
    assert await _redis_commands_issued(redis) > before + 1


async def test_after_the_documented_reset_the_app_still_sends_its_event(
    redis_app: tuple[SecurityConfig, RateLimitManager],
) -> None:
    config, app = redis_app
    agent = Mock(send_event=AsyncMock())
    await app.initialize_agent(agent)
    block = None
    request = MockGuardRequest(path="/x", client_host="203.0.113.9")
    await _exhaust(app)
    await rate_limit_handler(config).reset()
    await _exhaust(app)

    tier = RateLimitTier("global", config.rate_limit, config.rate_limit_window)
    block = await app.check_rate_limit_tiers(
        request, "203.0.113.9", _error_response, [tier], config
    )
    assert block is not None
    await app.report_rate_limit_block(request, "203.0.113.9", block, tier, config)

    assert app.agent_handler is agent
    agent.send_event.assert_awaited()


async def test_the_reset_clears_the_rate_limit_strikes_and_keeps_the_detection_strikes(
    redis_app: tuple[SecurityConfig, RateLimitManager],
) -> None:
    config, app = redis_app
    redis = app.redis_handler
    for _ in range(3):
        await record_shared_violation(redis, "203.0.113.9")
    now = time.time()
    await redis.record_detection_strikes(
        "203.0.113.9", ("xss",), now, now - 3600, 3600, 10_000
    )
    violations = f"{config.redis_prefix}rate_limit:violations:203.0.113.9"
    detection = f"{config.redis_prefix}detection:strikes:203.0.113.9"

    await rate_limit_handler(config).reset()

    async with redis.get_connection() as conn:
        assert await conn.exists(violations) == 0
        assert await conn.zcard(detection) == 1
