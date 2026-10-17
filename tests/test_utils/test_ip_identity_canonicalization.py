from unittest.mock import AsyncMock, Mock

import pytest

from guard_core.core.checks.helpers import _increment_suspicious_counts
from guard_core.core.checks.implementations.emergency_mode import EmergencyModeCheck
from guard_core.core.checks.implementations.ip_security import IpSecurityCheck
from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.handlers.ratelimit_handler import check_rate_limit_by_ip
from guard_core.handlers.redis_handler import redis_handler as redis_handler_factory
from guard_core.models import SecurityConfig
from guard_core.utils import _extract_from_forwarded_header, extract_client_ip
from tests.conftest import MockGuardRequest

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


def _trusted_proxy_config(**overrides: object) -> SecurityConfig:
    return SecurityConfig(
        trusted_proxies=["127.0.0.1"], trusted_proxy_depth=1, **overrides
    )


def _build_mock_middleware(config: SecurityConfig) -> Mock:
    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(
        return_value=Mock(status_code=403, headers={})
    )
    middleware.route_resolver = Mock()
    middleware.route_resolver.should_bypass_check = Mock(return_value=False)
    middleware.geo_ip_handler = None
    return middleware


@pytest.mark.parametrize("raw_form", SIX_RAW_FORMS)
async def test_extract_client_ip_canonicalizes_six_forms_via_connecting_host(
    raw_form: str,
) -> None:
    request = MockGuardRequest(client_host=raw_form)
    config = SecurityConfig()

    resolved = await extract_client_ip(request, config)

    assert resolved == CANONICAL_BY_RAW_FORM[raw_form]


@pytest.mark.parametrize("raw_form", SIX_RAW_FORMS)
async def test_extract_client_ip_canonicalizes_six_forms_via_forwarded_header(
    raw_form: str,
) -> None:
    request = MockGuardRequest(
        headers={"X-Forwarded-For": raw_form}, client_host="127.0.0.1"
    )
    config = _trusted_proxy_config()

    resolved = await extract_client_ip(request, config)

    assert resolved == CANONICAL_BY_RAW_FORM[raw_form]


async def test_zone_identifier_link_local_stays_distinct_by_design() -> None:
    with_zone = await extract_client_ip(
        MockGuardRequest(client_host="fe80::1%eth0"), SecurityConfig()
    )
    without_zone = await extract_client_ip(
        MockGuardRequest(client_host="fe80::1"), SecurityConfig()
    )

    assert with_zone == "fe80::1%eth0"
    assert without_zone == "fe80::1"
    assert with_zone != without_zone


async def test_ipv4_mapped_addresses_with_different_zones_stay_distinct_by_design() -> (
    None
):
    zone_eth0 = await extract_client_ip(
        MockGuardRequest(client_host="::ffff:1.2.3.4%eth0"), SecurityConfig()
    )
    zone_eth1 = await extract_client_ip(
        MockGuardRequest(client_host="::ffff:1.2.3.4%eth1"), SecurityConfig()
    )

    assert zone_eth0 == "::ffff:1.2.3.4%eth0"
    assert zone_eth1 == "::ffff:1.2.3.4%eth1"
    assert zone_eth0 != zone_eth1


async def test_ipv4_mapped_address_without_zone_still_canonicalizes_to_bare_ipv4() -> (
    None
):
    resolved = await extract_client_ip(
        MockGuardRequest(client_host="::ffff:1.2.3.4"), SecurityConfig()
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
async def test_direct_and_forwarded_paths_agree_on_bracketed_ipv6_identity(
    bracketed_form: str,
) -> None:
    direct = await extract_client_ip(
        MockGuardRequest(client_host=bracketed_form), SecurityConfig()
    )
    forwarded = await extract_client_ip(
        MockGuardRequest(
            headers={"X-Forwarded-For": bracketed_form}, client_host="127.0.0.1"
        ),
        _trusted_proxy_config(),
    )
    unbracketed_direct = await extract_client_ip(
        MockGuardRequest(client_host="2001:db8::1"), SecurityConfig()
    )

    assert direct == forwarded == unbracketed_direct == "2001:db8::1"


async def test_direct_path_non_ip_client_host_stays_raw_not_attacker_supplied() -> None:
    resolved = await extract_client_ip(
        MockGuardRequest(client_host="garbage"), SecurityConfig()
    )

    assert resolved == "garbage"


@pytest.mark.parametrize("raw_form", SIX_RAW_FORMS)
async def test_ban_ip_canonicalizes_six_forms(raw_form: str) -> None:
    await ip_ban_manager.ban_ip(raw_form, 60, "test")
    assert await ip_ban_manager.is_ip_banned(CANONICAL_BY_RAW_FORM[raw_form]) is True


async def test_ban_ip_then_is_ip_banned_with_a_different_spelling() -> None:
    await ip_ban_manager.ban_ip("2001:DB8::1", 60, "test")

    assert await ip_ban_manager.is_ip_banned("2001:db8::1") is True
    assert (
        await ip_ban_manager.is_ip_banned("2001:0db8:0000:0000:0000:0000:0000:0001")
        is True
    )


async def test_unban_ip_with_a_different_spelling_lifts_the_ban() -> None:
    await ip_ban_manager.ban_ip("2001:DB8::1", 60, "test")

    await ip_ban_manager.unban_ip("2001:db8::1")

    assert await ip_ban_manager.is_ip_banned("2001:DB8::1") is False


async def test_ban_ip_cidr_entry_is_not_canonicalized() -> None:
    await ip_ban_manager.ban_ip("10.0.0.0/24", 60, "test")

    assert await ip_ban_manager.is_ip_banned("10.0.0.5") is True


@pytest.mark.parametrize(
    ("form_a", "form_b", "canonical"),
    [
        ("2001:0db8::1", "2001:DB8::1", "2001:db8::1"),
        ("::ffff:1.2.3.4", "1.2.3.4", "1.2.3.4"),
    ],
)
async def test_ban_via_one_textual_form_blocks_request_arriving_in_another_form(
    form_a: str,
    form_b: str,
    canonical: str,
    security_config_redis: SecurityConfig,
) -> None:
    handler = redis_handler_factory(security_config_redis)
    await handler.initialize()
    try:
        await ip_ban_manager.initialize_redis(handler)

        config = _trusted_proxy_config()
        request_a = MockGuardRequest(
            headers={"X-Forwarded-For": form_a}, client_host="127.0.0.1"
        )
        ip_from_a = await extract_client_ip(request_a, config)
        assert ip_from_a == canonical

        await ip_ban_manager.ban_ip(ip_from_a, 60, "test_ban")
        ip_ban_manager.banned_ips.clear()

        request_b = MockGuardRequest(
            headers={"X-Forwarded-For": form_b}, client_host="127.0.0.1"
        )
        request_b.state.client_ip = await extract_client_ip(request_b, config)
        request_b.state.route_config = None
        assert request_b.state.client_ip == canonical

        middleware = _build_mock_middleware(security_config_redis)
        ip_security_check = IpSecurityCheck(middleware)

        response = await ip_security_check.check(request_b)

        assert response is not None
        assert response.status_code == 403
        assert await ip_ban_manager.is_ip_banned(canonical) is True
    finally:
        await ip_ban_manager.unban_ip(canonical)
        ip_ban_manager.redis_handler = None
        await handler.close()


@pytest.mark.parametrize(
    ("form_a", "form_b", "canonical"),
    [
        ("2001:0db8::1", "2001:DB8::1", "2001:db8::1"),
        ("::ffff:1.2.3.4", "1.2.3.4", "1.2.3.4"),
    ],
)
async def test_rate_limit_bucket_shared_across_textual_forms(
    form_a: str,
    form_b: str,
    canonical: str,
    security_config_redis: SecurityConfig,
) -> None:
    security_config_redis.rate_limit = 1
    security_config_redis.rate_limit_window = 60
    handler = redis_handler_factory(security_config_redis)
    await handler.initialize()
    try:
        config = _trusted_proxy_config()
        request_a = MockGuardRequest(
            headers={"X-Forwarded-For": form_a}, client_host="127.0.0.1"
        )
        request_b = MockGuardRequest(
            headers={"X-Forwarded-For": form_b}, client_host="127.0.0.1"
        )
        ip_from_a = await extract_client_ip(request_a, config)
        ip_from_b = await extract_client_ip(request_b, config)
        assert ip_from_a == ip_from_b == canonical

        endpoint_path = f"proof-{canonical.replace('.', '-').replace(':', '-')}"
        first = await check_rate_limit_by_ip(
            ip_from_a,
            security_config_redis,
            redis_handler=handler,
            endpoint_path=endpoint_path,
        )
        second = await check_rate_limit_by_ip(
            ip_from_b,
            security_config_redis,
            redis_handler=handler,
            endpoint_path=endpoint_path,
        )

        assert first is True
        assert second is False
    finally:
        await handler.close()


async def test_ipv4_mapped_and_bare_ipv4_share_one_suspicious_activity_counter() -> (
    None
):
    config = _trusted_proxy_config()
    middleware = _build_mock_middleware(config)
    middleware.suspicious_request_counts = {}

    request_mapped = MockGuardRequest(
        headers={"X-Forwarded-For": "::ffff:1.2.3.4"}, client_host="127.0.0.1"
    )
    request_bare = MockGuardRequest(
        headers={"X-Forwarded-For": "1.2.3.4"}, client_host="127.0.0.1"
    )
    ip_mapped = await extract_client_ip(request_mapped, config)
    ip_bare = await extract_client_ip(request_bare, config)
    assert ip_mapped == ip_bare == "1.2.3.4"

    _increment_suspicious_counts(middleware, ip_mapped, "sql_injection")
    _increment_suspicious_counts(middleware, ip_bare, "xss")

    assert list(middleware.suspicious_request_counts.keys()) == ["1.2.3.4"]
    assert middleware.suspicious_request_counts["1.2.3.4"] == {
        "sql_injection": 1,
        "xss": 1,
    }


async def test_emergency_whitelist_mapped_entry_matches_canonical_client_ip() -> None:
    config = SecurityConfig(
        emergency_mode=True, emergency_whitelist=["::ffff:203.0.113.5"]
    )
    middleware = _build_mock_middleware(config)
    check = EmergencyModeCheck(middleware)

    request = MockGuardRequest(client_host="203.0.113.5")
    request.state.client_ip = "203.0.113.5"

    response = await check.check(request)

    assert response is None


async def test_emergency_check_denies_unparseable_client_ip() -> None:
    config = SecurityConfig(emergency_mode=True, emergency_whitelist=["203.0.113.5"])
    middleware = _build_mock_middleware(config)
    check = EmergencyModeCheck(middleware)

    request = MockGuardRequest(client_host=None)
    request.state.client_ip = "unknown"

    response = await check.check(request)

    assert response is not None
    middleware.create_error_response.assert_awaited_once_with(
        status_code=503, default_message="Service temporarily unavailable"
    )
