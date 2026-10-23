import warnings
from typing import Any

import pytest

from guard_core.models import SyncSecurityConfig


class _StubGeoIPHandler:
    @property
    def is_initialized(self) -> bool:
        return False

    def initialize(self) -> None:
        return

    def initialize_redis(self, redis_handler: Any) -> None:
        return

    def initialize_agent(self, agent_handler: Any) -> None:
        return

    def get_country(self, ip: str) -> str | None:
        return None

    def refresh(self) -> None:
        return

    def close(self) -> None:
        return


def test_geo_ip_handler_without_country_rules_does_not_warn() -> None:
    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        SyncSecurityConfig(geo_ip_handler=_StubGeoIPHandler())

    inert_warnings = [r for r in records if "never be consulted" in str(r.message)]
    assert inert_warnings == []


def test_geo_ip_handler_with_blocked_countries_does_not_warn() -> None:
    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        SyncSecurityConfig(geo_ip_handler=_StubGeoIPHandler(), blocked_countries=["US"])

    inert_warnings = [r for r in records if "never be consulted" in str(r.message)]
    assert inert_warnings == []


def test_no_geo_ip_handler_does_not_warn_about_inert_configuration() -> None:
    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        SyncSecurityConfig()

    inert_warnings = [r for r in records if "never be consulted" in str(r.message)]
    assert inert_warnings == []


def test_lazy_init_default_true() -> None:
    assert SyncSecurityConfig().lazy_init is True


def test_lazy_init_accepts_false() -> None:
    assert SyncSecurityConfig(lazy_init=False).lazy_init is False


def test_geo_ip_db_max_age_default_86400() -> None:
    assert SyncSecurityConfig().geo_ip_db_max_age == 86400


def test_geo_ip_db_max_age_accepts_custom() -> None:
    assert SyncSecurityConfig(geo_ip_db_max_age=7200).geo_ip_db_max_age == 7200


def test_geo_ip_db_max_age_rejects_below_3600() -> None:
    with pytest.raises(ValueError):
        SyncSecurityConfig(geo_ip_db_max_age=3599)


def test_geo_ip_db_max_age_rejects_above_604800() -> None:
    with pytest.raises(ValueError):
        SyncSecurityConfig(geo_ip_db_max_age=604801)


def test_cloud_ip_store_default_none() -> None:
    assert SyncSecurityConfig().cloud_ip_store is None


def test_cloud_ip_store_accepts_protocol_instance() -> None:
    from guard_core.sync.handlers.cloud_ip_stores import InMemoryCloudIpStore

    store = InMemoryCloudIpStore()
    assert SyncSecurityConfig(cloud_ip_store=store).cloud_ip_store is store
