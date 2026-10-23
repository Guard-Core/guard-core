from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.helpers import _increment_suspicious_counts
from guard_core.sync.core.checks.implementations.emergency_mode import (
    EmergencyModeCheck,
)
from guard_core.sync.core.checks.implementations.ip_security import IpSecurityCheck
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from guard_core.sync.handlers.ratelimit_handler import check_rate_limit_by_ip
from guard_core.sync.handlers.redis_handler import (
    redis_handler as redis_handler_factory,
)
from guard_core.sync.utils import _extract_from_forwarded_header, extract_client_ip
from tests.test_sync.conftest import SyncMockGuardRequest

SIX_RAW_FORMS = [
    "2001:db8::1",
    "2001:0db8::1",
    "2001:DB8::1",
    "2001:db8:0:0:0:0:0:1",
    "::ffff:1.2.3.4",
    "1.2.3.4",
]

CANONICAL_BY_RAW_FORM = {
    "2001:db8::1": "2001:db8::1",
    "2001:0db8::1": "2001:db8::1",
    "2001:DB8::1": "2001:db8::1",
    "2001:db8:0:0:0:0:0:1": "2001:db8::1",
    "::ffff:1.2.3.4": "1.2.3.4",
    "1.2.3.4": "1.2.3.4",
}


def _trusted_proxy_config(**overrides: object) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        trusted_proxies=["127.0.0.1"], trusted_proxy_depth=1, **overrides
    )


def _build_mock_middleware(config: SyncSecurityConfig) -> Mock:
    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(
        return_value=Mock(status_code=403, headers={})
    )
    middleware.route_resolver = Mock()
    middleware.route_resolver.should_bypass_check = Mock(return_value=False)
    middleware.geo_ip_handler = None
    return middleware


@pytest.mark.parametrize("raw_form", SIX_RAW_FORMS)
def test_extract_client_ip_canonicalizes_six_forms_via_connecting_host(
    raw_form: str,
) -> None:
    request = SyncMockGuardRequest(client_host=raw_form)
    config = SyncSecurityConfig()

    resolved = extract_client_ip(request, config)

    assert resolved == CANONICAL_BY_RAW_FORM[raw_form]


@pytest.mark.parametrize("raw_form", SIX_RAW_FORMS)
def test_extract_client_ip_canonicalizes_six_forms_via_forwarded_header(
    raw_form: str,
) -> None:
    request = SyncMockGuardRequest(
        headers={"X-Forwarded-For": raw_form}, client_host="127.0.0.1"
    )
    config = _trusted_proxy_config()

    resolved = extract_client_ip(request, config)

    assert resolved == CANONICAL_BY_RAW_FORM[raw_form]


def test_zone_identifier_is_not_part_of_the_identity() -> None:
    with_zone = extract_client_ip(
        SyncMockGuardRequest(client_host="fe80::1%eth0"), SyncSecurityConfig()
    )
    without_zone = extract_client_ip(
        SyncMockGuardRequest(client_host="fe80::1"), SyncSecurityConfig()
    )

    assert with_zone == "fe80::1"
    assert without_zone == "fe80::1"


def test_ipv4_mapped_addresses_with_different_zones_are_one_ipv4_identity() -> None:
    zone_eth0 = extract_client_ip(
        SyncMockGuardRequest(client_host="::ffff:1.2.3.4%eth0"), SyncSecurityConfig()
    )
    zone_eth1 = extract_client_ip(
        SyncMockGuardRequest(client_host="::ffff:1.2.3.4%eth1"), SyncSecurityConfig()
    )

    assert zone_eth0 == "1.2.3.4"
    assert zone_eth1 == "1.2.3.4"


def test_ipv4_mapped_address_without_zone_still_canonicalizes_to_bare_ipv4() -> None:
    resolved = extract_client_ip(
        SyncMockGuardRequest(client_host="::ffff:1.2.3.4"), SyncSecurityConfig()
    )

    assert resolved == "1.2.3.4"


def test_forwarded_header_candidate_with_port_suffix_resolves_to_the_address() -> None:
    result = _extract_from_forwarded_header("1.2.3.4:8080", 1)

    assert result == "1.2.3.4"


def test_forwarded_header_bracketed_ipv6_candidate_is_accepted_and_canonicalized() -> (
    None
):
    result = _extract_from_forwarded_header("[2001:0DB8::1]", 1)

    assert result == "2001:db8::1"


@pytest.mark.parametrize("bracketed_form", ["[2001:db8::1]", "[2001:0DB8::1]"])
def test_direct_and_forwarded_paths_agree_on_bracketed_ipv6_identity(
    bracketed_form: str,
) -> None:
    direct = extract_client_ip(
        SyncMockGuardRequest(client_host=bracketed_form), SyncSecurityConfig()
    )
    forwarded = extract_client_ip(
        SyncMockGuardRequest(
            headers={"X-Forwarded-For": bracketed_form}, client_host="127.0.0.1"
        ),
        _trusted_proxy_config(),
    )
    unbracketed_direct = extract_client_ip(
        SyncMockGuardRequest(client_host="2001:db8::1"), SyncSecurityConfig()
    )

    assert direct == forwarded == unbracketed_direct == "2001:db8::1"


def test_direct_path_non_ip_client_host_stays_raw_not_attacker_supplied() -> None:
    resolved = extract_client_ip(
        SyncMockGuardRequest(client_host="garbage"), SyncSecurityConfig()
    )

    assert resolved == "garbage"


@pytest.mark.parametrize("raw_form", SIX_RAW_FORMS)
def test_ban_ip_canonicalizes_six_forms(raw_form: str) -> None:
    ip_ban_manager.ban_ip(raw_form, 60, "test")
    assert ip_ban_manager.is_ip_banned(CANONICAL_BY_RAW_FORM[raw_form]) is True


def test_ban_ip_then_is_ip_banned_with_a_different_spelling() -> None:
    ip_ban_manager.ban_ip("2001:DB8::1", 60, "test")

    assert ip_ban_manager.is_ip_banned("2001:db8::1") is True
    assert (
        ip_ban_manager.is_ip_banned("2001:0db8:0000:0000:0000:0000:0000:0001") is True
    )


def test_unban_ip_with_a_different_spelling_lifts_the_ban() -> None:
    ip_ban_manager.ban_ip("2001:DB8::1", 60, "test")

    ip_ban_manager.unban_ip("2001:db8::1")

    assert ip_ban_manager.is_ip_banned("2001:DB8::1") is False


def test_ban_ip_cidr_entry_is_not_canonicalized() -> None:
    ip_ban_manager.ban_ip("10.0.0.0/24", 60, "test")

    assert ip_ban_manager.is_ip_banned("10.0.0.5") is True


@pytest.mark.parametrize(
    ("form_a", "form_b", "canonical"),
    [
        ("2001:0db8::1", "2001:DB8::1", "2001:db8::1"),
        ("::ffff:1.2.3.4", "1.2.3.4", "1.2.3.4"),
    ],
)
def test_ban_via_one_textual_form_blocks_request_arriving_in_another_form(
    form_a: str,
    form_b: str,
    canonical: str,
    security_config_redis: SyncSecurityConfig,
) -> None:
    handler = redis_handler_factory(security_config_redis)
    handler.initialize()
    try:
        ip_ban_manager.initialize_redis(handler)

        config = _trusted_proxy_config()
        request_a = SyncMockGuardRequest(
            headers={"X-Forwarded-For": form_a}, client_host="127.0.0.1"
        )
        ip_from_a = extract_client_ip(request_a, config)
        assert ip_from_a == canonical

        ip_ban_manager.ban_ip(ip_from_a, 60, "test_ban")
        ip_ban_manager.banned_ips.clear()

        request_b = SyncMockGuardRequest(
            headers={"X-Forwarded-For": form_b}, client_host="127.0.0.1"
        )
        request_b.state.client_ip = extract_client_ip(request_b, config)
        request_b.state.route_config = None
        assert request_b.state.client_ip == canonical

        middleware = _build_mock_middleware(security_config_redis)
        ip_security_check = IpSecurityCheck(middleware)

        response = ip_security_check.check(request_b)

        assert response is not None
        assert response.status_code == 403
        assert ip_ban_manager.is_ip_banned(canonical) is True
    finally:
        ip_ban_manager.unban_ip(canonical)
        ip_ban_manager.redis_handler = None
        handler.close()


@pytest.mark.parametrize(
    ("form_a", "form_b", "canonical"),
    [
        ("2001:0db8::1", "2001:DB8::1", "2001:db8::1"),
        ("::ffff:1.2.3.4", "1.2.3.4", "1.2.3.4"),
    ],
)
def test_rate_limit_bucket_shared_across_textual_forms(
    form_a: str,
    form_b: str,
    canonical: str,
    security_config_redis: SyncSecurityConfig,
) -> None:
    security_config_redis.rate_limit = 1
    security_config_redis.rate_limit_window = 60
    handler = redis_handler_factory(security_config_redis)
    handler.initialize()
    try:
        config = _trusted_proxy_config()
        request_a = SyncMockGuardRequest(
            headers={"X-Forwarded-For": form_a}, client_host="127.0.0.1"
        )
        request_b = SyncMockGuardRequest(
            headers={"X-Forwarded-For": form_b}, client_host="127.0.0.1"
        )
        ip_from_a = extract_client_ip(request_a, config)
        ip_from_b = extract_client_ip(request_b, config)
        assert ip_from_a == ip_from_b == canonical

        endpoint_path = f"proof-{canonical.replace('.', '-').replace(':', '-')}"
        first = check_rate_limit_by_ip(
            ip_from_a,
            security_config_redis,
            redis_handler=handler,
            endpoint_path=endpoint_path,
        )
        second = check_rate_limit_by_ip(
            ip_from_b,
            security_config_redis,
            redis_handler=handler,
            endpoint_path=endpoint_path,
        )

        assert first is True
        assert second is False
    finally:
        handler.close()


def test_ipv4_mapped_and_bare_ipv4_share_one_suspicious_activity_counter() -> None:
    config = _trusted_proxy_config()
    middleware = _build_mock_middleware(config)
    middleware.suspicious_request_counts = {}

    request_mapped = SyncMockGuardRequest(
        headers={"X-Forwarded-For": "::ffff:1.2.3.4"}, client_host="127.0.0.1"
    )
    request_bare = SyncMockGuardRequest(
        headers={"X-Forwarded-For": "1.2.3.4"}, client_host="127.0.0.1"
    )
    ip_mapped = extract_client_ip(request_mapped, config)
    ip_bare = extract_client_ip(request_bare, config)
    assert ip_mapped == ip_bare == "1.2.3.4"

    _increment_suspicious_counts(middleware, ip_mapped, "sql_injection")
    _increment_suspicious_counts(middleware, ip_bare, "xss")

    assert list(middleware.suspicious_request_counts.keys()) == ["1.2.3.4"]
    assert middleware.suspicious_request_counts["1.2.3.4"] == {
        "sql_injection": 1,
        "xss": 1,
    }


def test_emergency_whitelist_mapped_entry_matches_canonical_client_ip() -> None:
    config = SyncSecurityConfig(
        emergency_mode=True, emergency_whitelist=["::ffff:203.0.113.5"]
    )
    middleware = _build_mock_middleware(config)
    check = EmergencyModeCheck(middleware)

    request = SyncMockGuardRequest(client_host="203.0.113.5")
    request.state.client_ip = "203.0.113.5"

    response = check.check(request)

    assert response is None


def test_emergency_check_denies_unparseable_client_ip() -> None:
    config = SyncSecurityConfig(
        emergency_mode=True, emergency_whitelist=["203.0.113.5"]
    )
    middleware = _build_mock_middleware(config)
    check = EmergencyModeCheck(middleware)

    request = SyncMockGuardRequest(client_host=None)
    request.state.client_ip = "unknown"

    response = check.check(request)

    assert response is not None
    middleware.create_error_response.assert_called_once_with(
        status_code=503, default_message="Service temporarily unavailable"
    )
