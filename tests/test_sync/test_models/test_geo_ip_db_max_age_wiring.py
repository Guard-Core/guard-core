from typing import Any, cast

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.ipinfo_handler import IPInfoManager


@pytest.fixture(autouse=True)
def _reset_ipinfo_singleton() -> object:
    IPInfoManager._instance = None
    yield
    IPInfoManager._instance = None


def test_geo_ip_db_max_age_reaches_auto_constructed_handler() -> None:
    config = SyncSecurityConfig(
        ipinfo_token="token123",
        blocked_countries=["CN"],
        geo_ip_db_max_age=7200,
    )
    assert cast(Any, config.geo_ip_handler)._max_age == 7200
