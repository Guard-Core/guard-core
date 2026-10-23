import logging
import re
from ipaddress import ip_address
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core._utils import detection_scan
from guard_core.core.checks.helpers import (
    _check_ip_blacklist,
    _check_ip_whitelist,
    _get_detection_disabled_reason,
    _get_effective_penetration_setting,
    _log_exception_safely,
    check_country_access,
    check_route_ip_access,
    check_user_agent_allowed,
    detect_penetration_patterns,
    extract_credential,
    is_ip_in_blacklist,
    is_ip_in_whitelist,
    is_referrer_domain_allowed,
)
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig


async def test_is_ip_in_blacklist_exact_match() -> None:
    assert is_ip_in_blacklist("1.2.3.4", ip_address("1.2.3.4"), ["1.2.3.4"]) is True


async def test_is_ip_in_blacklist_cidr_match() -> None:
    assert (
        is_ip_in_blacklist("10.0.0.5", ip_address("10.0.0.5"), ["10.0.0.0/8"]) is True
    )


async def test_is_ip_in_blacklist_no_match() -> None:
    assert is_ip_in_blacklist("5.5.5.5", ip_address("5.5.5.5"), ["1.2.3.4"]) is False


async def test_is_ip_in_whitelist_empty() -> None:
    assert is_ip_in_whitelist("1.2.3.4", ip_address("1.2.3.4"), []) is None


async def test_is_ip_in_whitelist_exact_match() -> None:
    assert is_ip_in_whitelist("1.2.3.4", ip_address("1.2.3.4"), ["1.2.3.4"]) is True


async def test_is_ip_in_whitelist_cidr_match() -> None:
    assert (
        is_ip_in_whitelist("10.0.0.5", ip_address("10.0.0.5"), ["10.0.0.0/8"]) is True
    )


async def test_is_ip_in_whitelist_no_match() -> None:
    assert is_ip_in_whitelist("5.5.5.5", ip_address("5.5.5.5"), ["1.2.3.4"]) is False


async def test_check_country_access_no_handler() -> None:
    rc = RouteConfig()
    assert check_country_access("1.2.3.4", rc, None) is None


async def test_check_country_access_blocked() -> None:
    rc = RouteConfig()
    rc.blocked_countries = ["CN"]
    geo = MagicMock()
    geo.get_country = MagicMock(return_value="CN")
    assert check_country_access("1.2.3.4", rc, geo) is False


async def test_check_country_access_not_blocked() -> None:
    rc = RouteConfig()
    rc.blocked_countries = ["CN"]
    geo = MagicMock()
    geo.get_country = MagicMock(return_value="US")
    assert check_country_access("1.2.3.4", rc, geo) is None


async def test_check_country_access_whitelisted() -> None:
    rc = RouteConfig()
    rc.whitelist_countries = ["US"]
    geo = MagicMock()
    geo.get_country = MagicMock(return_value="US")
    assert check_country_access("1.2.3.4", rc, geo) is True


async def test_check_country_access_not_whitelisted() -> None:
    rc = RouteConfig()
    rc.whitelist_countries = ["US"]
    geo = MagicMock()
    geo.get_country = MagicMock(return_value="CN")
    assert check_country_access("1.2.3.4", rc, geo) is False


async def test_check_country_access_whitelist_no_country() -> None:
    rc = RouteConfig()
    rc.whitelist_countries = ["US"]
    geo = MagicMock()
    geo.get_country = MagicMock(return_value=None)
    assert check_country_access("1.2.3.4", rc, geo) is False


async def test_check_country_access_blocked_and_whitelisted() -> None:
    rc = RouteConfig()
    rc.blocked_countries = ["CN"]
    rc.whitelist_countries = ["US"]
    geo = MagicMock()
    geo.get_country = MagicMock(return_value="US")
    assert check_country_access("1.2.3.4", rc, geo) is True


async def test_check_ip_blacklist_empty() -> None:
    rc = RouteConfig()
    assert _check_ip_blacklist("1.2.3.4", ip_address("1.2.3.4"), rc) is False


async def test_check_ip_blacklist_match() -> None:
    rc = RouteConfig()
    rc.ip_blacklist = ["1.2.3.4"]
    assert _check_ip_blacklist("1.2.3.4", ip_address("1.2.3.4"), rc) is True


async def test_check_ip_whitelist_empty() -> None:
    rc = RouteConfig()
    result = _check_ip_whitelist("1.2.3.4", ip_address("1.2.3.4"), rc)
    assert result is None


async def test_check_route_ip_access_blacklisted() -> None:
    rc = RouteConfig()
    rc.ip_blacklist = ["1.2.3.4"]
    mw = MagicMock()
    mw.geo_ip_handler = None
    result = await check_route_ip_access("1.2.3.4", rc, mw)
    assert result is False


async def test_check_route_ip_access_whitelisted() -> None:
    rc = RouteConfig()
    rc.ip_whitelist = ["1.2.3.4"]
    mw = MagicMock()
    mw.geo_ip_handler = None
    result = await check_route_ip_access("1.2.3.4", rc, mw)
    assert result is True


async def test_check_route_ip_access_invalid_ip() -> None:
    rc = RouteConfig()
    mw = MagicMock()
    result = await check_route_ip_access("not_an_ip", rc, mw)
    assert result is False


async def test_check_route_ip_access_no_restrictions() -> None:
    rc = RouteConfig()
    mw = MagicMock()
    mw.geo_ip_handler = None
    result = await check_route_ip_access("1.2.3.4", rc, mw)
    assert result is None


async def test_check_route_ip_access_unknown_identity_no_restrictions() -> None:
    rc = RouteConfig()
    mw = MagicMock()
    mw.geo_ip_handler = None
    result = await check_route_ip_access("unknown", rc, mw)
    assert result is None


async def test_check_route_ip_access_unknown_identity_with_whitelist_blocked() -> None:
    rc = RouteConfig()
    rc.ip_whitelist = ["1.2.3.4"]
    mw = MagicMock()
    mw.geo_ip_handler = None
    result = await check_route_ip_access("unknown", rc, mw)
    assert result is False


async def test_check_route_ip_access_unknown_identity_with_blacklist_passes() -> None:
    rc = RouteConfig()
    rc.ip_blacklist = ["1.2.3.4"]
    mw = MagicMock()
    mw.geo_ip_handler = None
    result = await check_route_ip_access("unknown", rc, mw)
    assert result is None


async def test_check_route_ip_access_unknown_whitelist_countries_blocked() -> None:
    rc = RouteConfig()
    rc.whitelist_countries = ["US"]
    mw = MagicMock()
    mw.geo_ip_handler = None
    result = await check_route_ip_access("unknown", rc, mw)
    assert result is False


async def test_check_route_ip_access_unknown_blocked_countries_passes() -> None:
    rc = RouteConfig()
    rc.blocked_countries = ["CN"]
    mw = MagicMock()
    mw.geo_ip_handler = None
    result = await check_route_ip_access("unknown", rc, mw)
    assert result is None


async def test_check_route_ip_access_country() -> None:
    rc = RouteConfig()
    rc.blocked_countries = ["CN"]
    mw = MagicMock()
    mw.geo_ip_handler = MagicMock()
    mw.geo_ip_handler.get_country = MagicMock(return_value="CN")
    result = await check_route_ip_access("1.2.3.4", rc, mw)
    assert result is False


async def test_check_route_ip_access_ip_whitelist_match_still_checks_country() -> None:
    rc = RouteConfig()
    rc.ip_whitelist = ["1.2.3.4"]
    rc.whitelist_countries = ["US"]
    mw = MagicMock()
    mw.geo_ip_handler = MagicMock()
    mw.geo_ip_handler.get_country = MagicMock(return_value="CN")
    result = await check_route_ip_access("1.2.3.4", rc, mw)
    assert result is False


async def test_check_route_ip_access_ip_whitelist_and_country_both_match() -> None:
    rc = RouteConfig()
    rc.ip_whitelist = ["1.2.3.4"]
    rc.whitelist_countries = ["US"]
    mw = MagicMock()
    mw.geo_ip_handler = MagicMock()
    mw.geo_ip_handler.get_country = MagicMock(return_value="US")
    result = await check_route_ip_access("1.2.3.4", rc, mw)
    assert result is True


async def test_check_user_agent_blocked_by_route() -> None:
    rc = RouteConfig()
    rc.blocked_user_agents = ["badbot"]
    config = MagicMock()
    result = await check_user_agent_allowed("badbot/1.0", rc, config)
    assert result is False


async def test_check_user_agent_allowed_by_route() -> None:
    rc = RouteConfig()
    rc.blocked_user_agents = ["badbot"]
    config = SecurityConfig(enable_redis=False)
    result = await check_user_agent_allowed("Mozilla/5.0", rc, config)
    assert result is True


def test_extract_credential_bearer() -> None:
    assert extract_credential("Bearer token123", "bearer") == ("token123", "")


def test_extract_credential_bearer_wrong_scheme() -> None:
    assert extract_credential("Basic creds", "bearer") == (
        None,
        "Missing or invalid Bearer token",
    )


def test_extract_credential_bearer_missing() -> None:
    assert extract_credential("", "bearer") == (None, "Missing or invalid Bearer token")


def test_extract_credential_basic() -> None:
    assert extract_credential("Basic dXNlcjpwYXNz", "basic") == ("dXNlcjpwYXNz", "")


def test_extract_credential_basic_wrong_scheme() -> None:
    assert extract_credential("Bearer token", "basic") == (
        None,
        "Missing or invalid Basic authentication",
    )


def test_extract_credential_custom() -> None:
    assert extract_credential("CustomScheme value", "custom") == (
        "CustomScheme value",
        "",
    )


def test_extract_credential_custom_missing() -> None:
    assert extract_credential("", "custom") == (None, "Missing custom authentication")


async def test_referrer_domain_valid() -> None:
    assert (
        is_referrer_domain_allowed("https://example.com/page", ["example.com"]) is True
    )


async def test_referrer_domain_subdomain() -> None:
    assert (
        is_referrer_domain_allowed("https://sub.example.com/", ["example.com"]) is True
    )


async def test_referrer_domain_allowed_scheme_prefixed_origin() -> None:
    assert (
        is_referrer_domain_allowed("https://example.com/page", ["https://example.com"])
        is True
    )


async def test_referrer_domain_allowed_origin_with_port() -> None:
    assert (
        is_referrer_domain_allowed(
            "https://example.com:8443/page", ["https://example.com:8443"]
        )
        is True
    )


async def test_referrer_domain_allowed_origin_with_path() -> None:
    assert (
        is_referrer_domain_allowed(
            "https://example.com/page", ["https://example.com/some/path"]
        )
        is True
    )


async def test_referrer_domain_allowed_bare_domain_with_trailing_slash() -> None:
    assert (
        is_referrer_domain_allowed("https://example.com/page", ["example.com/"]) is True
    )


async def test_referrer_domain_allowed_scheme_prefixed_subdomain_match() -> None:
    assert (
        is_referrer_domain_allowed(
            "https://sub.example.com/page", ["https://example.com"]
        )
        is True
    )


async def test_referrer_domain_allowed_scheme_prefixed_non_match() -> None:
    assert (
        is_referrer_domain_allowed("https://evil.com/page", ["https://example.com"])
        is False
    )


async def test_referrer_domain_malformed_referrer_url_returns_false() -> None:
    assert is_referrer_domain_allowed("http://[::1", ["example.com"]) is False


async def test_referrer_domain_invalid() -> None:
    assert is_referrer_domain_allowed("https://evil.com/", ["example.com"]) is False


async def test_referrer_domain_bad_url() -> None:
    assert (
        is_referrer_domain_allowed("not a url at all \\x00", ["example.com"]) is False
    )


async def test_get_effective_penetration_setting_default() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=True)
    enabled, route_specific = _get_effective_penetration_setting(config, None)
    assert enabled is True
    assert route_specific is None


async def test_get_effective_penetration_setting_route_override() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=True)
    rc = RouteConfig()
    rc.enable_suspicious_detection = False
    enabled, route_specific = _get_effective_penetration_setting(config, rc)
    assert enabled is False
    assert route_specific is False


async def test_get_detection_disabled_reason_route_override() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=True)
    reason = _get_detection_disabled_reason(config, False)
    assert reason == "disabled_by_decorator"


async def test_get_detection_disabled_reason_not_enabled() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=False)
    reason = _get_detection_disabled_reason(config, None)
    assert reason == "not_enabled"


async def test_detect_penetration_patterns_enabled() -> None:
    from unittest.mock import patch

    from guard_core.detection_result import DetectionResult

    config = SecurityConfig(enable_redis=False, enable_penetration_detection=True)
    from tests.conftest import MockGuardRequest

    req = MockGuardRequest(path="/test")
    with patch(
        "guard_core.core.checks.helpers.detect_penetration_attempt",
        new_callable=AsyncMock,
        return_value=DetectionResult(is_threat=False, trigger_info=""),
    ):
        result = await detect_penetration_patterns(req, None, config, lambda *_: False)
    assert result.is_threat is False


async def test_detect_penetration_patterns_disabled() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=False)
    from tests.conftest import MockGuardRequest

    req = MockGuardRequest(path="/test")
    result = await detect_penetration_patterns(req, None, config, lambda *_: False)
    assert result.is_threat is False
    assert result.trigger_info == "not_enabled"


async def test_detect_penetration_patterns_bypassed() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=True)
    from tests.conftest import MockGuardRequest

    req = MockGuardRequest(path="/test")
    result = await detect_penetration_patterns(req, None, config, lambda *_: True)
    assert result.is_threat is False


def test_is_ip_in_blacklist_cidr_entry_not_containing_ip() -> None:
    assert (
        is_ip_in_blacklist(
            "10.0.0.1", ip_address("10.0.0.1"), ["192.168.0.0/16", "172.16.0.0/12"]
        )
        is False
    )


def test_is_ip_in_blacklist_plain_entry_no_match() -> None:
    assert (
        is_ip_in_blacklist("10.0.0.1", ip_address("10.0.0.1"), ["1.2.3.4", "5.6.7.8"])
        is False
    )


def test_is_ip_in_whitelist_cidr_entry_not_containing_ip() -> None:
    assert (
        is_ip_in_whitelist(
            "10.0.0.1", ip_address("10.0.0.1"), ["192.168.0.0/16", "172.16.0.0/12"]
        )
        is False
    )


def test_is_ip_in_whitelist_plain_entry_no_match() -> None:
    assert (
        is_ip_in_whitelist("10.0.0.1", ip_address("10.0.0.1"), ["1.2.3.4", "5.6.7.8"])
        is False
    )


async def test_check_user_agent_allowed_route_blocklist_no_match() -> None:
    config = SecurityConfig(blocked_user_agents=[])
    route_config = RouteConfig()
    route_config.blocked_user_agents = ["badbot"]
    assert await check_user_agent_allowed("Mozilla/5.0", route_config, config) is True


async def test_check_user_agent_allowed_no_route_config_uses_global() -> None:
    config = SecurityConfig(blocked_user_agents=[])
    assert await check_user_agent_allowed("Mozilla/5.0", None, config) is True


class _RaisingLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        raise RuntimeError("log sink filter exploded")


def test_log_exception_safely_swallows_when_logger_succeeds() -> None:
    logger = MagicMock()

    _log_exception_safely(logger, "escalation failed for %s", "9.9.9.9")

    logger.exception.assert_called_once_with("escalation failed for %s", "9.9.9.9")


def test_log_exception_safely_falls_back_to_module_logger_when_logger_raises(
    caplog: pytest.LogCaptureFixture,
) -> None:
    broken_logger = logging.getLogger("test.guard_core.broken_logger")
    broken_logger.addFilter(_RaisingLogFilter())
    try:
        with caplog.at_level(logging.ERROR, logger="guard_core.core.checks.helpers"):
            _log_exception_safely(broken_logger, "escalation failed for %s", "9.9.9.9")
    finally:
        broken_logger.filters.clear()

    fallback_records = [
        r for r in caplog.records if r.name == "guard_core.core.checks.helpers"
    ]
    assert len(fallback_records) == 1
    assert fallback_records[0].getMessage() == "escalation failed for 9.9.9.9"


async def test_check_user_agent_allowed_route_blocklist_uses_inline_safe_path() -> None:
    calls: list[int] = []
    original = detection_scan._search_user_agent_windows

    def _spy(compiled: re.Pattern[str], text: str) -> re.Match[str] | None:
        calls.append(len(text))
        return original(compiled, text)

    rc = RouteConfig()
    rc.blocked_user_agents = ["badbot"]
    config = SecurityConfig(blocked_user_agents=[])
    with patch.object(detection_scan, "_search_user_agent_windows", _spy):
        result = await check_user_agent_allowed("badbot/1.0", rc, config)

    assert result is False
    assert calls == [len("badbot/1.0")]


async def test_check_user_agent_allowed_route_blocklist_sees_the_whole_user_agent() -> (
    None
):
    from guard_core.utils import _MAX_USER_AGENT_MATCH_LENGTH

    marker = "zzq_route_ua_whole_marker_zzq"
    rc = RouteConfig()
    rc.blocked_user_agents = [marker]
    config = SecurityConfig(blocked_user_agents=[])

    beyond_old_cap = "a" * _MAX_USER_AGENT_MATCH_LENGTH + marker
    within_cap = marker + "a" * 10

    assert await check_user_agent_allowed(beyond_old_cap, rc, config) is False
    assert await check_user_agent_allowed(within_cap, rc, config) is False
