import logging
from datetime import datetime, timezone
from typing import Any, cast

import pytest

from guard_core.models import DynamicRules, SyncSecurityConfig
from guard_core.sync.handlers.ipinfo_handler import IPInfoManager
from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler


def test_security_config_validation() -> None:
    valid_config = SyncSecurityConfig(
        whitelist=["10.0.0.0/24", "192.168.1.1"],
        blacklist=["203.0.113.0/25"],
    )
    assert valid_config.whitelist == ("10.0.0.0/24", "192.168.1.1")


def test_invalid_ip_validation() -> None:
    with pytest.raises(ValueError):
        SyncSecurityConfig(whitelist=["invalid.ip"], blacklist=["256.0.0.0"])


def test_cloud_provider_validation_rejects_unknown_provider() -> None:
    with pytest.raises(ValueError, match="Unknown cloud providers"):
        SyncSecurityConfig(block_cloud_providers={"AWS", "INVALID"})


def test_security_config_none_whitelist() -> None:
    config = SyncSecurityConfig(whitelist=None)
    assert config.whitelist is None


def test_none_cloud_providers() -> None:
    config = SyncSecurityConfig(block_cloud_providers=None)
    assert config.block_cloud_providers is None


def test_missing_ipinfo_token() -> None:
    with pytest.raises(ValueError):
        SyncSecurityConfig(blocked_countries=["US"])

    with pytest.raises(ValueError):
        SyncSecurityConfig(whitelist_countries=["US"])

    with pytest.raises(ValueError):
        SyncSecurityConfig(blocked_countries=["US"], whitelist_countries=["US"])


class ValidGeoIPHandler:
    @property
    def is_initialized(self) -> bool:
        return True

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


def test_geo_ip_handler_validation() -> None:
    ipinfo = IPInfoManager(token="test")
    config = SyncSecurityConfig(geo_ip_handler=ipinfo, blocked_countries=["US"])
    assert cast(IPInfoManager, config.geo_ip_handler) is ipinfo

    valid_instance = ValidGeoIPHandler()
    config = SyncSecurityConfig(geo_ip_handler=valid_instance, blocked_countries=["US"])
    assert cast(ValidGeoIPHandler, config.geo_ip_handler) is valid_instance

    config = SyncSecurityConfig(geo_ip_handler=None)
    assert config.geo_ip_handler is None

    class InvalidGeoIPHandler:
        pass

    invalid_handler = cast(SyncGeoIPHandler, InvalidGeoIPHandler())
    with pytest.raises(ValueError):
        SyncSecurityConfig(geo_ip_handler=invalid_handler)


def test_geo_ip_handler_ipinfo_token_fallback() -> None:
    config = SyncSecurityConfig(ipinfo_token="test", whitelist_countries=["US"])
    assert config.geo_ip_handler is not None
    assert type(config.geo_ip_handler).__name__ == "IPInfoManager"


def test_geo_ip_handler_async_methods() -> None:
    handler = ValidGeoIPHandler()

    handler.initialize()
    assert handler.is_initialized is True

    mock_redis = object()
    handler.initialize_redis(mock_redis)

    mock_agent = object()
    handler.initialize_agent(mock_agent)

    result = handler.get_country("192.168.1.1")
    assert result is None


def test_validate_trusted_proxies() -> None:
    config = SyncSecurityConfig(trusted_proxies=["127.0.0.1", "192.168.1.0/24"])
    assert "127.0.0.1" in config.trusted_proxies
    assert "192.168.1.0/24" in config.trusted_proxies

    with pytest.raises(ValueError, match="Invalid proxy IP or CIDR range"):
        SyncSecurityConfig(trusted_proxies=["invalid-ip"])

    config = SyncSecurityConfig(trusted_proxies=[])
    assert config.trusted_proxies == ()


def test_validate_trusted_proxies_accepts_unix_token() -> None:
    config = SyncSecurityConfig(trusted_proxies=["unix", "127.0.0.1"])
    assert "unix" in config.trusted_proxies
    assert "127.0.0.1" in config.trusted_proxies


def test_trusted_proxies_prefix_zero_warns(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core.models"):
        SyncSecurityConfig(trusted_proxies=["0.0.0.0/0"])

    assert any("every peer is trusted" in record.message for record in caplog.records)


def test_trusted_proxies_without_prefix_zero_does_not_warn(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core.models"):
        SyncSecurityConfig(trusted_proxies=["127.0.0.1", "unix"])

    assert not any(
        "every peer is trusted" in record.message for record in caplog.records
    )


def test_whitelist_prefix_zero_ipv4_warns(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core.models"):
        SyncSecurityConfig(whitelist=["0.0.0.0/0"])

    assert any(
        "every address is whitelisted" in record.message for record in caplog.records
    )


def test_whitelist_prefix_zero_ipv6_warns(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core.models"):
        SyncSecurityConfig(whitelist=["::/0"])

    assert any(
        "every address is whitelisted" in record.message for record in caplog.records
    )


def test_whitelist_prefix_zero_mixed_list_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core.models"):
        SyncSecurityConfig(whitelist=["10.0.0.0/8", "0.0.0.0/0"])

    assert any(
        "every address is whitelisted" in record.message for record in caplog.records
    )


def test_whitelist_prefix_zero_warns_once_per_construction(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core.models"):
        SyncSecurityConfig(whitelist=["0.0.0.0/0", "::/0"])

    matches = [
        record
        for record in caplog.records
        if "every address is whitelisted" in record.message
    ]
    assert len(matches) == 1


def test_whitelist_specific_network_does_not_warn(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core.models"):
        SyncSecurityConfig(whitelist=["10.0.0.0/8"])

    assert not any(
        "every address is whitelisted" in record.message for record in caplog.records
    )


def test_whitelist_empty_list_does_not_warn(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core.models"):
        SyncSecurityConfig(whitelist=[])

    assert not any(
        "every address is whitelisted" in record.message for record in caplog.records
    )


def test_whitelist_none_does_not_warn(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core.models"):
        SyncSecurityConfig(whitelist=None)

    assert not any(
        "every address is whitelisted" in record.message for record in caplog.records
    )


def test_validate_whitelist_rejects_unix_token() -> None:
    with pytest.raises(ValueError, match="Invalid IP or CIDR range"):
        SyncSecurityConfig(whitelist=["unix"])


def test_validate_blacklist_rejects_unix_token() -> None:
    with pytest.raises(ValueError, match="Invalid IP or CIDR range"):
        SyncSecurityConfig(blacklist=["unix"])


def test_validate_proxy_depth() -> None:
    config = SyncSecurityConfig(trusted_proxy_depth=2)
    assert config.trusted_proxy_depth == 2

    with pytest.raises(ValueError, match="trusted_proxy_depth must be at least 1"):
        SyncSecurityConfig(trusted_proxy_depth=0)


def test_muted_event_types_validation_invalid() -> None:
    with pytest.raises(ValueError, match="Unknown event types"):
        SyncSecurityConfig(muted_event_types={"nonexistent_event_type"})


def test_muted_metric_types_validation_invalid() -> None:
    with pytest.raises(ValueError, match="Unknown metric types"):
        SyncSecurityConfig(muted_metric_types={"nonexistent_metric_type"})


def test_muted_event_types_validation_valid() -> None:
    config = SyncSecurityConfig(muted_event_types={"penetration_attempt"})
    assert config.muted_event_types == {"penetration_attempt"}


def test_muted_metric_types_validation_valid() -> None:
    config = SyncSecurityConfig(muted_metric_types={"response_time"})
    assert config.muted_metric_types == {"response_time"}


def test_security_config_auth_verifier_defaults_none() -> None:
    config = SyncSecurityConfig()
    assert config.auth_verifier is None


def test_security_config_auth_verifier_accepts_callable() -> None:
    def verifier(request: object, credential: str) -> object:
        return credential

    config = SyncSecurityConfig(auth_verifier=verifier)
    assert config.auth_verifier is verifier


def test_dynamic_rules_rejects_non_positive_auto_ban_threshold() -> None:
    with pytest.raises(ValueError):
        DynamicRules(
            rule_id="r1",
            version=1,
            timestamp=datetime.now(timezone.utc),
            auto_ban_threshold=0,
        )


def test_dynamic_rules_rejects_non_positive_auto_ban_duration() -> None:
    with pytest.raises(ValueError):
        DynamicRules(
            rule_id="r1",
            version=1,
            timestamp=datetime.now(timezone.utc),
            auto_ban_duration=0,
        )
