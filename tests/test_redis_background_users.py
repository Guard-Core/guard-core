from collections.abc import Generator
from pathlib import Path

import pytest

from guard_core.handlers.ipinfo_handler import IPInfoManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_URL, suite_redis_prefix


@pytest.fixture
def redis_manager() -> Generator[RedisManager, None, None]:
    yield RedisManager(
        SecurityConfig(
            enable_redis=True,
            redis_url=REDIS_URL,
            redis_prefix=suite_redis_prefix("wp419users"),
        )
    )


async def test_close_stops_every_registered_background_user_first(
    redis_manager: RedisManager,
) -> None:
    order: list[str] = []

    async def stop() -> None:
        order.append("stopped")

    redis_manager.register_background_user(stop)
    redis_manager.register_background_user(stop)
    await redis_manager.close()

    assert order == ["stopped"]


async def test_a_geo_manager_bound_to_redis_is_stopped_by_its_close(
    redis_manager: RedisManager, tmp_path: Path
) -> None:
    IPInfoManager._instance = None
    geo = IPInfoManager("token", tmp_path / "country_asn.mmdb")
    geo._bind_redis_handler(redis_manager)

    assert geo._stop_background_load in redis_manager._background_user_set()
    await redis_manager.close()
    IPInfoManager._instance = None
