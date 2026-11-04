from collections.abc import Generator
from pathlib import Path

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.ipinfo_handler import IPInfoManager
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.test_sync.conftest import REDIS_URL, suite_redis_prefix


@pytest.fixture
def redis_manager() -> Generator[RedisManager, None, None]:
    yield RedisManager(
        SyncSecurityConfig(
            enable_redis=True,
            redis_url=REDIS_URL,
            redis_prefix=suite_redis_prefix("wp419users"),
        )
    )


def test_close_stops_every_registered_background_user_first(
    redis_manager: RedisManager,
) -> None:
    order: list[str] = []

    def stop() -> None:
        order.append("stopped")

    redis_manager.register_background_user(stop)
    redis_manager.register_background_user(stop)
    redis_manager.close()

    assert order == ["stopped"]


def test_a_geo_manager_bound_to_redis_is_stopped_by_its_close(
    redis_manager: RedisManager, tmp_path: Path
) -> None:
    IPInfoManager._instance = None
    geo = IPInfoManager("token", tmp_path / "country_asn.mmdb")
    geo._bind_redis_handler(redis_manager)

    assert geo._stop_background_load in redis_manager._background_users
    redis_manager.close()
    IPInfoManager._instance = None
