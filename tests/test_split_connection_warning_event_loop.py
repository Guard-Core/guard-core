import asyncio
import logging

import pytest

from guard_core._utils.app_managers import AppManagers
from guard_core.models import SecurityConfig

LOGGER = "guard_core.handlers.app_managers"


class _Manager:
    pass


def _config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=True,
        redis_url="redis://one.invalid:6379/0",
        redis_prefix="wp461:",
        enable_agent=False,
    )


def test_different_event_loops_are_named(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger=LOGGER)
    managers: AppManagers[_Manager] = AppManagers(
        "wp461", warns_on_split_connection=True
    )
    default, config = _Manager(), _config()

    async def bind() -> _Manager:
        return managers.bind(config, default, _Manager)

    loop_one, loop_two = asyncio.new_event_loop(), asyncio.new_event_loop()
    try:
        assert loop_one.run_until_complete(bind()) is default
        other = _config()

        async def bind_other() -> _Manager:
            return managers.bind(other, default, _Manager)

        assert loop_two.run_until_complete(bind_other()) is not default
    finally:
        loop_one.close()
        loop_two.close()
    (message,) = [r.getMessage() for r in caplog.records if r.name == LOGGER]
    assert "on one event loop" in message and "on another event loop" in message
    assert "redis_max_connections" not in message
