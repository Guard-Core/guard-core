from collections.abc import Callable
from importlib.util import find_spec as real_find_spec
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from guard_core.models import SecurityConfig, cloud_blocking_enabled
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.implementations import (
    CloudIpRefreshCheck,
    CloudProviderCheck,
    IpSecurityCheck,
)
from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler


def _blocking_find_spec(*blocked_names: str) -> Callable[[str, str | None], object]:
    def fake_find_spec(name: str, package: str | None = None) -> object:
        if name in blocked_names:
            return None
        return real_find_spec(name, package)

    return fake_find_spec


def test_default_security_check_requires_is_empty() -> None:
    assert SecurityCheck.requires == ()
    assert IpSecurityCheck.requires == ()


def test_cloud_provider_check_requires_cloud_extra() -> None:
    assert CloudProviderCheck.requires == ("cloud",)


def test_cloud_ip_refresh_check_requires_cloud_extra() -> None:
    assert CloudIpRefreshCheck.requires == ("cloud",)


def test_country_rules_without_maxminddb_raises_named_extra(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("importlib.util.find_spec", _blocking_find_spec("maxminddb"))

    with pytest.raises(ValidationError) as exc_info:
        SecurityConfig(blocked_countries={"US"})

    assert "pip install guard-core[geo]" in str(exc_info.value)
    assert not isinstance(exc_info.value, ImportError)


def test_ipinfo_token_without_maxminddb_raises_validation_error_not_import_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("importlib.util.find_spec", _blocking_find_spec("maxminddb"))

    with pytest.raises(ValidationError) as exc_info:
        SecurityConfig(ipinfo_token="token123", blocked_countries=["CN"])

    assert "pip install guard-core[geo]" in str(exc_info.value)


def test_custom_geo_ip_handler_without_maxminddb_validates_cleanly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("importlib.util.find_spec", _blocking_find_spec("maxminddb"))
    handler = MagicMock(spec=SyncGeoIPHandler)

    config = SecurityConfig(geo_ip_handler=handler, blocked_countries={"US"})

    assert config.geo_ip_handler is handler


def test_custom_geo_ip_handler_without_country_rules_or_maxminddb_validates_cleanly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("importlib.util.find_spec", _blocking_find_spec("maxminddb"))
    handler = MagicMock(spec=SyncGeoIPHandler)

    config = SecurityConfig(geo_ip_handler=handler)

    assert config.geo_ip_handler is handler


def test_an_unset_enable_redis_with_a_connection_field_raises_named_extra(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("importlib.util.find_spec", _blocking_find_spec("redis"))

    with pytest.raises(ValidationError) as exc_info:
        SecurityConfig(redis_prefix="app:")

    assert "pip install guard-core[redis]" in str(exc_info.value)


def test_an_unset_enable_redis_without_a_connection_field_needs_no_redis_package(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("importlib.util.find_spec", _blocking_find_spec("redis"))

    assert SecurityConfig().enable_redis is False


def test_enable_redis_false_without_redis_package_does_not_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("importlib.util.find_spec", _blocking_find_spec("redis"))

    config = SecurityConfig(enable_redis=False)

    assert config.enable_redis is False


def test_block_cloud_providers_without_cloud_packages_raises_named_extra(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "importlib.util.find_spec", _blocking_find_spec("aiohttp", "requests")
    )

    with pytest.raises(ValidationError) as exc_info:
        SecurityConfig(block_cloud_providers={"AWS"})

    assert "pip install guard-core[cloud]" in str(exc_info.value)


def test_block_cloud_providers_none_without_cloud_packages_does_not_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "importlib.util.find_spec", _blocking_find_spec("aiohttp", "requests")
    )

    config = SecurityConfig(block_cloud_providers=None)

    assert config.block_cloud_providers is None


def test_block_cloud_providers_with_only_requests_available_does_not_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("importlib.util.find_spec", _blocking_find_spec("aiohttp"))

    config = SecurityConfig(block_cloud_providers={"AWS"})

    assert config.block_cloud_providers == {"AWS"}


def test_enable_dynamic_rules_without_cloud_packages_raises_named_extra(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "importlib.util.find_spec", _blocking_find_spec("aiohttp", "requests")
    )

    with pytest.raises(ValidationError) as exc_info:
        SecurityConfig(
            enable_dynamic_rules=True,
            enable_agent=True,
            agent_api_key="test-key",
        )

    assert "pip install guard-core[cloud]" in str(exc_info.value)


def test_enable_dynamic_rules_false_without_cloud_packages_does_not_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "importlib.util.find_spec", _blocking_find_spec("aiohttp", "requests")
    )

    config = SecurityConfig(enable_dynamic_rules=False, block_cloud_providers=None)

    assert config.block_cloud_providers is None


@pytest.mark.parametrize(
    "block_cloud_providers, dynamic_rule_kwargs",
    [
        (None, {}),
        ({"AWS"}, {}),
        (
            None,
            {"enable_dynamic_rules": True, "enable_agent": True, "agent_api_key": "k"},
        ),
        (
            {"AWS"},
            {"enable_dynamic_rules": True, "enable_agent": True, "agent_api_key": "k"},
        ),
    ],
)
def test_cloud_extras_requirement_agrees_with_check_applies_to(
    block_cloud_providers: set[str] | None,
    dynamic_rule_kwargs: dict[str, object],
) -> None:
    config = SecurityConfig(
        block_cloud_providers=block_cloud_providers, **dynamic_rule_kwargs
    )

    requires_cloud_extra = cloud_blocking_enabled(config)

    assert CloudProviderCheck.applies_to(config, ()) is requires_cloud_extra
    assert CloudIpRefreshCheck.applies_to(config, ()) is requires_cloud_extra
