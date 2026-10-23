import logging
from ipaddress import ip_address
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.helpers import (
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
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.detection_engine.compiler import PatternCompiler


def test_is_ip_in_blacklist_exact_match() -> None:
    assert is_ip_in_blacklist("1.2.3.4", ip_address("1.2.3.4"), ["1.2.3.4"]) is True


def test_is_ip_in_blacklist_cidr_match() -> None:
    assert (
        is_ip_in_blacklist("10.0.0.5", ip_address("10.0.0.5"), ["10.0.0.0/8"]) is True
    )


def test_is_ip_in_blacklist_no_match() -> None:
    assert is_ip_in_blacklist("5.5.5.5", ip_address("5.5.5.5"), ["1.2.3.4"]) is False


def test_is_ip_in_whitelist_empty() -> None:
    assert is_ip_in_whitelist("1.2.3.4", ip_address("1.2.3.4"), []) is None


def test_is_ip_in_whitelist_exact_match() -> None:
    assert is_ip_in_whitelist("1.2.3.4", ip_address("1.2.3.4"), ["1.2.3.4"]) is True


def test_is_ip_in_whitelist_cidr_match() -> None:
    assert (
        is_ip_in_whitelist("10.0.0.5", ip_address("10.0.0.5"), ["10.0.0.0/8"]) is True
    )


def test_is_ip_in_whitelist_no_match() -> None:
    assert is_ip_in_whitelist("5.5.5.5", ip_address("5.5.5.5"), ["1.2.3.4"]) is False


def test_check_country_access_no_handler() -> None:
    rc = RouteConfig()
    assert check_country_access("1.2.3.4", rc, None) is None


def test_check_country_access_blocked() -> None:
    rc = RouteConfig()
    rc.blocked_countries = ["CN"]
    geo = MagicMock()
    geo.get_country = MagicMock(return_value="CN")
    assert check_country_access("1.2.3.4", rc, geo) is False


def test_check_country_access_not_blocked() -> None:
    rc = RouteConfig()
    rc.blocked_countries = ["CN"]
    geo = MagicMock()
    geo.get_country = MagicMock(return_value="US")
    assert check_country_access("1.2.3.4", rc, geo) is None


def test_check_country_access_whitelisted() -> None:
    rc = RouteConfig()
    rc.whitelist_countries = ["US"]
    geo = MagicMock()
    geo.get_country = MagicMock(return_value="US")
    assert check_country_access("1.2.3.4", rc, geo) is True


def test_check_country_access_not_whitelisted() -> None:
    rc = RouteConfig()
    rc.whitelist_countries = ["US"]
    geo = MagicMock()
    geo.get_country = MagicMock(return_value="CN")
    assert check_country_access("1.2.3.4", rc, geo) is False


def test_check_country_access_whitelist_no_country() -> None:
    rc = RouteConfig()
    rc.whitelist_countries = ["US"]
    geo = MagicMock()
    geo.get_country = MagicMock(return_value=None)
    assert check_country_access("1.2.3.4", rc, geo) is False


def test_check_country_access_blocked_and_whitelisted() -> None:
    rc = RouteConfig()
    rc.blocked_countries = ["CN"]
    rc.whitelist_countries = ["US"]
    geo = MagicMock()
    geo.get_country = MagicMock(return_value="US")
    assert check_country_access("1.2.3.4", rc, geo) is True


def test_check_ip_blacklist_empty() -> None:
    rc = RouteConfig()
    assert _check_ip_blacklist("1.2.3.4", ip_address("1.2.3.4"), rc) is False


def test_check_ip_blacklist_match() -> None:
    rc = RouteConfig()
    rc.ip_blacklist = ["1.2.3.4"]
    assert _check_ip_blacklist("1.2.3.4", ip_address("1.2.3.4"), rc) is True


def test_check_ip_whitelist_empty() -> None:
    rc = RouteConfig()
    result = _check_ip_whitelist("1.2.3.4", ip_address("1.2.3.4"), rc)
    assert result is None


def test_check_route_ip_access_blacklisted() -> None:
    rc = RouteConfig()
    rc.ip_blacklist = ["1.2.3.4"]
    mw = MagicMock()
    mw.geo_ip_handler = None
    result = check_route_ip_access("1.2.3.4", rc, mw)
    assert result is False


def test_check_route_ip_access_whitelisted() -> None:
    rc = RouteConfig()
    rc.ip_whitelist = ["1.2.3.4"]
    mw = MagicMock()
    mw.geo_ip_handler = None
    result = check_route_ip_access("1.2.3.4", rc, mw)
    assert result is True


def test_check_route_ip_access_invalid_ip() -> None:
    rc = RouteConfig()
    mw = MagicMock()
    result = check_route_ip_access("not_an_ip", rc, mw)
    assert result is False


def test_check_route_ip_access_no_restrictions() -> None:
    rc = RouteConfig()
    mw = MagicMock()
    mw.geo_ip_handler = None
    result = check_route_ip_access("1.2.3.4", rc, mw)
    assert result is None


def test_check_route_ip_access_unknown_identity_no_restrictions() -> None:
    rc = RouteConfig()
    mw = MagicMock()
    mw.geo_ip_handler = None
    result = check_route_ip_access("unknown", rc, mw)
    assert result is None


def test_check_route_ip_access_unknown_identity_with_whitelist_blocked() -> None:
    rc = RouteConfig()
    rc.ip_whitelist = ["1.2.3.4"]
    mw = MagicMock()
    mw.geo_ip_handler = None
    result = check_route_ip_access("unknown", rc, mw)
    assert result is False


def test_check_route_ip_access_unknown_identity_with_blacklist_passes() -> None:
    rc = RouteConfig()
    rc.ip_blacklist = ["1.2.3.4"]
    mw = MagicMock()
    mw.geo_ip_handler = None
    result = check_route_ip_access("unknown", rc, mw)
    assert result is None


def test_check_route_ip_access_unknown_whitelist_countries_blocked() -> None:
    rc = RouteConfig()
    rc.whitelist_countries = ["US"]
    mw = MagicMock()
    mw.geo_ip_handler = None
    result = check_route_ip_access("unknown", rc, mw)
    assert result is False


def test_check_route_ip_access_unknown_blocked_countries_passes() -> None:
    rc = RouteConfig()
    rc.blocked_countries = ["CN"]
    mw = MagicMock()
    mw.geo_ip_handler = None
    result = check_route_ip_access("unknown", rc, mw)
    assert result is None


def test_check_route_ip_access_country() -> None:
    rc = RouteConfig()
    rc.blocked_countries = ["CN"]
    mw = MagicMock()
    mw.geo_ip_handler = MagicMock()
    mw.geo_ip_handler.get_country = MagicMock(return_value="CN")
    result = check_route_ip_access("1.2.3.4", rc, mw)
    assert result is False


def test_check_route_ip_access_ip_whitelist_match_still_checks_country() -> None:
    rc = RouteConfig()
    rc.ip_whitelist = ["1.2.3.4"]
    rc.whitelist_countries = ["US"]
    mw = MagicMock()
    mw.geo_ip_handler = MagicMock()
    mw.geo_ip_handler.get_country = MagicMock(return_value="CN")
    result = check_route_ip_access("1.2.3.4", rc, mw)
    assert result is False


def test_check_route_ip_access_ip_whitelist_and_country_both_match() -> None:
    rc = RouteConfig()
    rc.ip_whitelist = ["1.2.3.4"]
    rc.whitelist_countries = ["US"]
    mw = MagicMock()
    mw.geo_ip_handler = MagicMock()
    mw.geo_ip_handler.get_country = MagicMock(return_value="US")
    result = check_route_ip_access("1.2.3.4", rc, mw)
    assert result is True


def test_check_user_agent_blocked_by_route() -> None:
    rc = RouteConfig()
    rc.blocked_user_agents = ["badbot"]
    config = MagicMock()
    result = check_user_agent_allowed("badbot/1.0", rc, config)
    assert result is False


def test_check_user_agent_allowed_by_route() -> None:
    rc = RouteConfig()
    rc.blocked_user_agents = ["badbot"]
    config = SyncSecurityConfig(enable_redis=False)
    result = check_user_agent_allowed("Mozilla/5.0", rc, config)
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


def test_referrer_domain_valid() -> None:
    assert (
        is_referrer_domain_allowed("https://example.com/page", ["example.com"]) is True
    )


def test_referrer_domain_subdomain() -> None:
    assert (
        is_referrer_domain_allowed("https://sub.example.com/", ["example.com"]) is True
    )


def test_referrer_domain_allowed_scheme_prefixed_origin() -> None:
    assert (
        is_referrer_domain_allowed("https://example.com/page", ["https://example.com"])
        is True
    )


def test_referrer_domain_allowed_origin_with_port() -> None:
    assert (
        is_referrer_domain_allowed(
            "https://example.com:8443/page", ["https://example.com:8443"]
        )
        is True
    )


def test_referrer_domain_allowed_origin_with_path() -> None:
    assert (
        is_referrer_domain_allowed(
            "https://example.com/page", ["https://example.com/some/path"]
        )
        is True
    )


def test_referrer_domain_allowed_bare_domain_with_trailing_slash() -> None:
    assert (
        is_referrer_domain_allowed("https://example.com/page", ["example.com/"]) is True
    )


def test_referrer_domain_allowed_scheme_prefixed_subdomain_match() -> None:
    assert (
        is_referrer_domain_allowed(
            "https://sub.example.com/page", ["https://example.com"]
        )
        is True
    )


def test_referrer_domain_allowed_scheme_prefixed_non_match() -> None:
    assert (
        is_referrer_domain_allowed("https://evil.com/page", ["https://example.com"])
        is False
    )


def test_referrer_domain_malformed_referrer_url_returns_false() -> None:
    assert is_referrer_domain_allowed("http://[::1", ["example.com"]) is False


def test_referrer_domain_invalid() -> None:
    assert is_referrer_domain_allowed("https://evil.com/", ["example.com"]) is False


def test_referrer_domain_bad_url() -> None:
    assert (
        is_referrer_domain_allowed("not a url at all \\x00", ["example.com"]) is False
    )


def test_get_effective_penetration_setting_default() -> None:
    config = SyncSecurityConfig(enable_redis=False, enable_penetration_detection=True)
    enabled, route_specific = _get_effective_penetration_setting(config, None)
    assert enabled is True
    assert route_specific is None


def test_get_effective_penetration_setting_route_override() -> None:
    config = SyncSecurityConfig(enable_redis=False, enable_penetration_detection=True)
    rc = RouteConfig()
    rc.enable_suspicious_detection = False
    enabled, route_specific = _get_effective_penetration_setting(config, rc)
    assert enabled is False
    assert route_specific is False


def test_get_detection_disabled_reason_route_override() -> None:
    config = SyncSecurityConfig(enable_redis=False, enable_penetration_detection=True)
    reason = _get_detection_disabled_reason(config, False)
    assert reason == "disabled_by_decorator"


def test_get_detection_disabled_reason_not_enabled() -> None:
    config = SyncSecurityConfig(enable_redis=False, enable_penetration_detection=False)
    reason = _get_detection_disabled_reason(config, None)
    assert reason == "not_enabled"


def test_detect_penetration_patterns_enabled() -> None:
    from guard_core.sync.detection_result import DetectionResult

    config = SyncSecurityConfig(enable_redis=False, enable_penetration_detection=True)
    from tests.test_sync.conftest import SyncMockGuardRequest

    req = SyncMockGuardRequest(path="/test")
    with patch(
        "guard_core.sync.core.checks.helpers.detect_penetration_attempt",
        return_value=DetectionResult(is_threat=False, trigger_info=""),
    ):
        result = detect_penetration_patterns(req, None, config, lambda *_: False)
    assert result.is_threat is False


def test_detect_penetration_patterns_disabled() -> None:
    config = SyncSecurityConfig(enable_redis=False, enable_penetration_detection=False)
    from tests.test_sync.conftest import SyncMockGuardRequest

    req = SyncMockGuardRequest(path="/test")
    result = detect_penetration_patterns(req, None, config, lambda *_: False)
    assert result.is_threat is False
    assert result.trigger_info == "not_enabled"


def test_detect_penetration_patterns_bypassed() -> None:
    config = SyncSecurityConfig(enable_redis=False, enable_penetration_detection=True)
    from tests.test_sync.conftest import SyncMockGuardRequest

    req = SyncMockGuardRequest(path="/test")
    result = detect_penetration_patterns(req, None, config, lambda *_: True)
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


def test_check_user_agent_allowed_route_blocklist_no_match() -> None:
    config = SyncSecurityConfig(blocked_user_agents=[])
    route_config = RouteConfig()
    route_config.blocked_user_agents = ["badbot"]
    assert check_user_agent_allowed("Mozilla/5.0", route_config, config) is True


def test_check_user_agent_allowed_no_route_config_uses_global() -> None:
    config = SyncSecurityConfig(blocked_user_agents=[])
    assert check_user_agent_allowed("Mozilla/5.0", None, config) is True


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
        with caplog.at_level(
            logging.ERROR, logger="guard_core.sync.core.checks.helpers"
        ):
            _log_exception_safely(broken_logger, "escalation failed for %s", "9.9.9.9")
    finally:
        broken_logger.filters.clear()

    fallback_records = [
        r for r in caplog.records if r.name == "guard_core.sync.core.checks.helpers"
    ]
    assert len(fallback_records) == 1
    assert fallback_records[0].getMessage() == "escalation failed for 9.9.9.9"


def test_check_user_agent_allowed_route_blocklist_uses_inline_safe_path() -> None:
    captured: list[bool] = []
    original = PatternCompiler.create_async_safe_finditer_matcher

    def _spy(
        self: PatternCompiler,
        pattern: str,
        timeout: float | None = None,
        inline_safe: bool = False,
    ) -> object:
        captured.append(inline_safe)
        return original(self, pattern, timeout=timeout, inline_safe=inline_safe)

    rc = RouteConfig()
    rc.blocked_user_agents = ["badbot"]
    config = SyncSecurityConfig(blocked_user_agents=[])
    with patch.object(PatternCompiler, "create_async_safe_finditer_matcher", _spy):
        result = check_user_agent_allowed("badbot/1.0", rc, config)

    assert result is False
    assert captured == [True]


def test_check_user_agent_allowed_route_blocklist_caps_subject_length() -> None:
    from guard_core.sync.utils import _MAX_USER_AGENT_MATCH_LENGTH

    marker = "zzq_route_ua_length_cap_marker_zzq"
    rc = RouteConfig()
    rc.blocked_user_agents = [marker]
    config = SyncSecurityConfig(blocked_user_agents=[])

    beyond_cap = "a" * _MAX_USER_AGENT_MATCH_LENGTH + marker
    within_cap = marker + "a" * 10

    assert check_user_agent_allowed(beyond_cap, rc, config) is True
    assert check_user_agent_allowed(within_cap, rc, config) is False
