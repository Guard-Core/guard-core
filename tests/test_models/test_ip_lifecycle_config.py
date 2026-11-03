import warnings

import pytest

from guard_core.models import SecurityConfig


class _StubGeoIPHandler:
    @property
    def is_initialized(self) -> bool:
        return False

    async def initialize(self) -> None:
        return

    async def initialize_redis(self, redis_handler: object) -> None:
        return

    async def initialize_agent(self, agent_handler: object) -> None:
        return

    def get_country(self, ip: str) -> str | None:
        return None

    async def refresh(self) -> None:
        return

    def close(self) -> None:
        return


def test_geo_ip_handler_without_country_rules_does_not_warn() -> None:
    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        SecurityConfig(geo_ip_handler=_StubGeoIPHandler())

    inert_warnings = [r for r in records if "never be consulted" in str(r.message)]
    assert inert_warnings == []


def test_geo_ip_handler_with_blocked_countries_does_not_warn() -> None:
    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        SecurityConfig(geo_ip_handler=_StubGeoIPHandler(), blocked_countries=["US"])

    inert_warnings = [r for r in records if "never be consulted" in str(r.message)]
    assert inert_warnings == []


def test_no_geo_ip_handler_does_not_warn_about_inert_configuration() -> None:
    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        SecurityConfig()

    inert_warnings = [r for r in records if "never be consulted" in str(r.message)]
    assert inert_warnings == []


def test_lazy_init_default_true() -> None:
    assert SecurityConfig().lazy_init is True


def test_lazy_init_accepts_false() -> None:
    assert SecurityConfig(lazy_init=False).lazy_init is False


def test_geo_ip_db_max_age_default_86400() -> None:
    assert SecurityConfig().geo_ip_db_max_age == 86400


def test_geo_ip_db_max_age_accepts_custom() -> None:
    assert SecurityConfig(geo_ip_db_max_age=7200).geo_ip_db_max_age == 7200


def test_geo_ip_db_max_age_rejects_below_3600() -> None:
    with pytest.raises(ValueError):
        SecurityConfig(geo_ip_db_max_age=3599)


def test_geo_ip_db_max_age_rejects_above_604800() -> None:
    with pytest.raises(ValueError):
        SecurityConfig(geo_ip_db_max_age=604801)


def test_cloud_ip_store_default_none() -> None:
    assert SecurityConfig().cloud_ip_store is None


def test_cloud_ip_store_accepts_protocol_instance() -> None:
    from guard_core.handlers.cloud_ip_stores import InMemoryCloudIpStore

    store = InMemoryCloudIpStore()
    assert SecurityConfig(cloud_ip_store=store).cloud_ip_store is store
