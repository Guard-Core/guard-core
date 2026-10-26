import asyncio

from guard_core._utils.app_managers import AppManagers
from guard_core.handlers._redis_shared_clients import connection_key_of
from guard_core.models import SecurityConfig

URL = "redis://one.invalid:6379/0"


class _Manager:
    pass


def _config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=True, redis_url=URL, redis_prefix="wp136-loop:", enable_agent=False
    )


def test_a_pool_key_needs_a_configured_redis() -> None:
    assert connection_key_of(SecurityConfig(enable_redis=False)) is None


def test_the_key_works_without_a_running_loop() -> None:
    assert connection_key_of(_config()) == connection_key_of(_config())


def test_same_prefix_and_settings_share_on_one_loop_and_split_across_loops() -> None:
    managers: AppManagers[_Manager] = AppManagers("wp136-loop")
    default, first, second, third = _Manager(), _config(), _config(), _config()

    async def bind(config: SecurityConfig) -> _Manager:
        return managers.bind(config, default, _Manager)

    loop_one = asyncio.new_event_loop()
    loop_two = asyncio.new_event_loop()
    try:
        assert loop_one.run_until_complete(bind(first)) is default
        assert loop_one.run_until_complete(bind(second)) is default
        assert loop_two.run_until_complete(bind(third)) is not default
        assert connection_key_of(first) != loop_two.run_until_complete(
            _key_in_loop(third)
        )
    finally:
        loop_one.close()
        loop_two.close()


async def _key_in_loop(config: SecurityConfig) -> object:
    return connection_key_of(config)
