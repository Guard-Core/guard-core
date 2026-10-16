import logging
import re
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest
from pytest_mock import MockerFixture

from guard_core.models import SecurityConfig
from guard_core.sync.detection_engine.compiler import PatternCompiler
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler
from guard_core.sync.utils import (
    check_ip_country,
    detect_penetration_attempt,
    is_ip_allowed,
    is_user_agent_allowed,
)


def test_is_ip_allowed(security_config: SecurityConfig, mocker: MockerFixture) -> None:
    mocker.patch("guard_core.sync.utils.check_ip_country", return_value=False)

    assert is_ip_allowed("127.0.0.1", security_config)
    assert not is_ip_allowed("192.168.1.1", security_config)

    empty_config = SecurityConfig(whitelist=[], blacklist=[])
    assert is_ip_allowed("127.0.0.1", empty_config)
    assert is_ip_allowed("192.168.1.1", empty_config)

    whitelist_config = SecurityConfig(whitelist=["127.0.0.1"])
    assert is_ip_allowed("127.0.0.1", whitelist_config)
    assert not is_ip_allowed("192.168.1.1", whitelist_config)

    blacklist_config = SecurityConfig(blacklist=["192.168.1.1"])
    assert is_ip_allowed("127.0.0.1", blacklist_config)
    assert not is_ip_allowed("192.168.1.1", blacklist_config)


def test_is_user_agent_allowed(security_config: SecurityConfig) -> None:
    assert is_user_agent_allowed("goodbot", security_config)
    assert not is_user_agent_allowed("badbot", security_config)


def test_is_user_agent_allowed_uses_inline_safe_path() -> None:
    captured: list[bool] = []
    original = PatternCompiler.create_async_safe_finditer_matcher

    def _spy(
        self: PatternCompiler,
        pattern: str,
        timeout: float | None = None,
        inline_safe: bool = False,
    ) -> Any:
        captured.append(inline_safe)
        return original(self, pattern, timeout=timeout, inline_safe=inline_safe)

    config = SecurityConfig(blocked_user_agents=["badbot"])
    with patch.object(PatternCompiler, "create_async_safe_finditer_matcher", _spy):
        result = is_user_agent_allowed("badbot/1.0", config)

    assert result is False
    assert captured == [True]


def test_is_user_agent_allowed_caps_subject_length_before_matching() -> None:
    from guard_core.sync.utils import _MAX_USER_AGENT_MATCH_LENGTH

    marker = "zzq_ua_length_cap_marker_zzq"
    beyond_cap = "a" * _MAX_USER_AGENT_MATCH_LENGTH + marker
    within_cap = marker + "a" * 10
    config = SecurityConfig(blocked_user_agents=[marker])

    assert is_user_agent_allowed(beyond_cap, config) is True
    assert is_user_agent_allowed(within_cap, config) is False


def test_detect_penetration_attempt() -> None:
    from tests.test_sync.conftest import SyncMockGuardRequest

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
        query_params={},
        body_content=b"",
    )
    _dpa = detect_penetration_attempt(request)

    result = _dpa.is_threat
    assert not result


def test_detect_penetration_attempt_xss() -> None:
    from tests.test_sync.conftest import SyncMockGuardRequest

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
        query_params={"param": "<script>alert('xss')</script>"},
        body_content=b"",
    )
    _dpa = detect_penetration_attempt(request)

    result, trigger = _dpa.is_threat, _dpa.trigger_info
    assert result
    assert "script" in trigger.lower()


def test_detect_penetration_attempt_sql_injection() -> None:
    from tests.test_sync.conftest import SyncMockGuardRequest

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
        query_params={"query": "UNION SELECT NULL--"},
        body_content=b"",
    )
    _dpa = detect_penetration_attempt(request)

    result = _dpa.is_threat
    assert result


def test_detect_penetration_attempt_directory_traversal() -> None:
    from tests.test_sync.conftest import SyncMockGuardRequest

    request = SyncMockGuardRequest(
        path="/../../etc/passwd",
        method="GET",
        headers={},
        client_host="127.0.0.1",
        query_params={},
        body_content=b"",
    )
    _dpa = detect_penetration_attempt(request)

    result = _dpa.is_threat
    assert result


def test_detect_penetration_attempt_command_injection() -> None:
    from tests.test_sync.conftest import SyncMockGuardRequest

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
        query_params={"cmd": "|cat /etc/passwd"},
        body_content=b"",
    )
    _dpa = detect_penetration_attempt(request)

    result = _dpa.is_threat
    assert result


def test_detect_penetration_attempt_path_manipulation() -> None:
    from tests.test_sync.conftest import SyncMockGuardRequest

    request = SyncMockGuardRequest(
        path="/../../../../etc/passwd",
        method="GET",
        headers={},
        client_host="127.0.0.1",
        query_params={},
        body_content=b"",
    )
    _dpa = detect_penetration_attempt(request)

    result = _dpa.is_threat
    assert result


def test_get_ip_country(mocker: MockerFixture) -> None:
    mock_ipinfo = mocker.patch("guard_core.sync.handlers.ipinfo_handler.IPInfoManager")
    mock_db = mock_ipinfo.return_value
    mock_db.get_country.return_value = "US"
    mock_db.reader = True

    config = SecurityConfig(
        blocked_countries=["CN"], geo_ip_handler=MagicMock(spec=SyncGeoIPHandler)
    )

    country = check_ip_country("1.1.1.1", config, mock_db)
    assert not country

    mock_db.get_country.return_value = "CN"
    country = check_ip_country("1.1.1.1", config, mock_db)
    assert country


def test_is_ip_allowed_cloud_providers(
    security_config: SecurityConfig, mocker: MockerFixture
) -> None:
    from guard_core.sync.handlers.cloud_handler import cloud_handler

    mocker.patch("guard_core.sync.utils.check_ip_country", return_value=True)
    mocker.patch.object(
        cloud_handler,
        "is_cloud_ip",
        side_effect=lambda ip, *_: ip.startswith("13."),
    )

    config = SecurityConfig(block_cloud_providers={"AWS"})

    assert is_ip_allowed("127.0.0.1", config)
    assert is_ip_allowed("13.59.255.255", config)
    assert is_ip_allowed("8.8.8.8", config)


def test_whitelisted_country(
    security_config: SecurityConfig, mocker: MockerFixture
) -> None:
    mock_ipinfo = MagicMock(spec=SyncGeoIPHandler)
    mock_ipinfo.get_country.return_value = "US"
    mock_ipinfo.reader = True

    security_config.geo_ip_handler = mock_ipinfo
    security_config.whitelist_countries = frozenset({"US"})

    assert not check_ip_country("8.8.8.8", security_config, mock_ipinfo)


def test_whitelist_countries_blocks_non_member(
    mocker: MockerFixture,
) -> None:
    mock_ipinfo = MagicMock(spec=SyncGeoIPHandler)
    mock_ipinfo.get_country.return_value = "FR"

    config = SecurityConfig(
        whitelist_countries=["US", "CA"], geo_ip_handler=mock_ipinfo
    )

    assert check_ip_country("8.8.8.8", config, mock_ipinfo)


def test_whitelist_countries_blocks_unknown_country(
    mocker: MockerFixture,
) -> None:
    mock_ipinfo = MagicMock(spec=SyncGeoIPHandler)
    mock_ipinfo.get_country.return_value = None

    config = SecurityConfig(
        whitelist_countries=["US", "CA"], geo_ip_handler=mock_ipinfo
    )

    assert check_ip_country("8.8.8.8", config, mock_ipinfo)


def test_whitelist_countries_overrides_blocked_countries(
    mocker: MockerFixture,
) -> None:
    mock_ipinfo = MagicMock(spec=SyncGeoIPHandler)
    mock_ipinfo.get_country.return_value = "US"

    with pytest.warns(UserWarning, match="blocked_countries is ignored"):
        config = SecurityConfig(
            blocked_countries=["US"],
            whitelist_countries=["US"],
            geo_ip_handler=mock_ipinfo,
        )

    assert not check_ip_country("8.8.8.8", config, mock_ipinfo)


def test_whitelist_countries_alone_blocks_non_member_via_is_ip_allowed(
    mocker: MockerFixture,
) -> None:
    mock_ipinfo = MagicMock(spec=SyncGeoIPHandler)
    mock_ipinfo.get_country.return_value = "DE"

    config = SecurityConfig(
        whitelist_countries=["US", "CA"], geo_ip_handler=mock_ipinfo
    )

    assert not is_ip_allowed("8.8.8.8", config, mock_ipinfo)


def test_whitelist_countries_alone_allows_member_via_is_ip_allowed(
    mocker: MockerFixture,
) -> None:
    mock_ipinfo = MagicMock(spec=SyncGeoIPHandler)
    mock_ipinfo.get_country.return_value = "US"

    config = SecurityConfig(
        whitelist_countries=["US", "CA"], geo_ip_handler=mock_ipinfo
    )

    assert is_ip_allowed("8.8.8.8", config, mock_ipinfo)


def test_loopback_ipv4_exempt_from_whitelist_countries() -> None:
    mock_ipinfo = MagicMock(spec=SyncGeoIPHandler)
    mock_ipinfo.get_country.return_value = None

    config = SecurityConfig(whitelist_countries=["US"], geo_ip_handler=mock_ipinfo)

    assert not check_ip_country("127.0.0.1", config, mock_ipinfo)
    mock_ipinfo.get_country.assert_not_called()


def test_loopback_ipv6_exempt_from_whitelist_countries() -> None:
    mock_ipinfo = MagicMock(spec=SyncGeoIPHandler)
    mock_ipinfo.get_country.return_value = None

    config = SecurityConfig(whitelist_countries=["US"], geo_ip_handler=mock_ipinfo)

    assert not check_ip_country("::1", config, mock_ipinfo)
    mock_ipinfo.get_country.assert_not_called()


def test_check_ip_country_non_ip_identity_is_not_treated_as_loopback() -> None:
    mock_ipinfo = MagicMock(spec=SyncGeoIPHandler)
    mock_ipinfo.get_country.return_value = "US"

    config = SecurityConfig(whitelist_countries=["US"], geo_ip_handler=mock_ipinfo)

    assert not check_ip_country("unknown", config, mock_ipinfo)
    mock_ipinfo.get_country.assert_called_once_with("unknown")


def test_cloud_provider_blocking(
    security_config: SecurityConfig, mocker: MockerFixture
) -> None:
    mocker.patch(
        "guard_core.sync.handlers.cloud_handler.cloud_handler.is_cloud_ip",
        return_value=True,
    )
    security_config.block_cloud_providers = frozenset({"AWS"})

    assert not is_ip_allowed("8.8.8.8", security_config)


def test_check_ip_access_leaves_cloud_blocking_to_the_cloud_provider_check(
    mocker: MockerFixture,
) -> None:
    from guard_core.sync.handlers.cloud_handler import cloud_handler
    from guard_core.sync.utils import check_ip_access

    is_cloud_ip = mocker.patch.object(cloud_handler, "is_cloud_ip", return_value=True)

    config = SecurityConfig(block_cloud_providers={"AWS"})

    result = check_ip_access("13.59.255.255", config)

    assert result.allowed is True
    is_cloud_ip.assert_not_called()


def test_check_ip_access_country_block_names_country(
    mocker: MockerFixture,
) -> None:
    from guard_core.sync.utils import check_ip_access

    mock_ipinfo = MagicMock(spec=SyncGeoIPHandler)
    mock_ipinfo.get_country.return_value = "RU"

    config = SecurityConfig(blocked_countries=["RU"], geo_ip_handler=mock_ipinfo)

    result = check_ip_access("8.8.8.8", config, mock_ipinfo)

    assert result.allowed is False
    assert "RU" in result.reason
    assert "allowlist/blocklist" not in result.reason


def test_check_ip_access_blocklist_block_keeps_existing_reason() -> None:
    from guard_core.sync.utils import check_ip_access

    config = SecurityConfig(blacklist=["192.168.1.1"])

    result = check_ip_access("192.168.1.1", config)

    assert result.allowed is False
    assert result.reason == "IP 192.168.1.1 not in global allowlist/blocklist"


def test_check_ip_access_whitelist_block_keeps_existing_reason() -> None:
    from guard_core.sync.utils import check_ip_access

    config = SecurityConfig(whitelist=["10.0.0.1"])

    result = check_ip_access("192.168.1.1", config)

    assert result.allowed is False
    assert result.reason == "IP 192.168.1.1 not in global allowlist/blocklist"


def test_check_ip_access_prefix_zero_whitelist_overrides_blacklist() -> None:
    from guard_core.sync.utils import check_ip_access

    config = SecurityConfig(whitelist=["0.0.0.0/0"], blacklist=["1.2.3.4"])

    result = check_ip_access("1.2.3.4", config)

    assert result.allowed is True
    assert result.reason == ""


def test_check_ip_access_loopback_passes_whitelist_countries_without_geoip() -> None:
    from guard_core.sync.utils import check_ip_access

    mock_ipinfo = MagicMock(spec=SyncGeoIPHandler)
    config = SecurityConfig(whitelist_countries=["US"], geo_ip_handler=mock_ipinfo)

    result = check_ip_access("127.0.0.1", config, mock_ipinfo)

    assert result.allowed is True
    mock_ipinfo.get_country.assert_not_called()


def test_check_ip_access_public_ip_with_no_country_stays_blocked() -> None:
    from guard_core.sync.utils import check_ip_access

    mock_ipinfo = MagicMock(spec=SyncGeoIPHandler)
    mock_ipinfo.get_country.return_value = None

    config = SecurityConfig(whitelist_countries=["US"], geo_ip_handler=mock_ipinfo)

    result = check_ip_access("8.8.8.8", config, mock_ipinfo)

    assert result.allowed is False


def test_check_ip_access_whitelisted_public_ip_with_no_country_passes() -> None:
    from guard_core.sync.utils import check_ip_access

    mock_ipinfo = MagicMock(spec=SyncGeoIPHandler)
    mock_ipinfo.get_country.return_value = None

    config = SecurityConfig(
        whitelist=["8.8.8.8"],
        whitelist_countries=["US"],
        geo_ip_handler=mock_ipinfo,
    )

    result = check_ip_access("8.8.8.8", config, mock_ipinfo)

    assert result.allowed is True
    mock_ipinfo.get_country.assert_not_called()


def test_check_ip_access_non_whitelisted_ip_from_bad_country_stays_blocked() -> None:
    from guard_core.sync.utils import check_ip_access

    mock_ipinfo = MagicMock(spec=SyncGeoIPHandler)
    mock_ipinfo.get_country.return_value = "FR"

    config = SecurityConfig(whitelist_countries=["US"], geo_ip_handler=mock_ipinfo)

    result = check_ip_access("8.8.8.8", config, mock_ipinfo)

    assert result.allowed is False


def test_check_ip_access_allowed_has_no_reason() -> None:
    from guard_core.sync.utils import check_ip_access

    result = check_ip_access("8.8.8.8", SecurityConfig())

    assert result.allowed is True


def test_check_ip_access_unknown_identity_with_no_lists_is_allowed() -> None:
    from guard_core.sync.utils import check_ip_access

    result = check_ip_access("unknown", SecurityConfig())

    assert result.allowed is True
    assert result.reason == ""


def test_check_ip_access_unknown_identity_blacklist_only_allowed() -> None:
    from guard_core.sync.utils import check_ip_access

    config = SecurityConfig(blacklist=["192.168.1.1"])

    result = check_ip_access("unknown", config)

    assert result.allowed is True
    assert result.reason == ""


def test_check_ip_access_unknown_identity_with_whitelist_is_blocked() -> None:
    from guard_core.sync.utils import check_ip_access

    config = SecurityConfig(whitelist=["10.0.0.1"])

    result = check_ip_access("unknown", config)

    assert result.allowed is False
    assert result.reason == "IP unknown not in global allowlist/blocklist"


def test_check_ip_access_unknown_identity_whitelist_countries_blocked() -> None:
    from guard_core.sync.utils import check_ip_access

    mock_ipinfo = MagicMock(spec=SyncGeoIPHandler)
    config = SecurityConfig(whitelist_countries=["US"], geo_ip_handler=mock_ipinfo)

    result = check_ip_access("unknown", config)

    assert result.allowed is False
    assert result.reason == "IP unknown not in global allowlist/blocklist"


def test_check_ip_access_unknown_identity_skips_country_and_cloud_checks(
    mocker: MockerFixture,
) -> None:
    from guard_core.sync.utils import check_ip_access

    mock_ipinfo = MagicMock(spec=SyncGeoIPHandler)
    config = SecurityConfig(
        blocked_countries=["RU"],
        block_cloud_providers={"AWS"},
        geo_ip_handler=mock_ipinfo,
    )
    mock_is_cloud_ip = mocker.patch(
        "guard_core.sync.handlers.cloud_handler.cloud_handler.is_cloud_ip"
    )

    result = check_ip_access("unknown", config, mock_ipinfo)

    assert result.allowed is True
    assert result.reason == ""
    mock_ipinfo.get_country.assert_not_called()
    mock_is_cloud_ip.assert_not_called()


def test_check_ip_access_malformed_ip_string_is_still_blocked() -> None:
    from guard_core.sync.utils import check_ip_access

    result = check_ip_access("not-an-ip", SecurityConfig())

    assert result.allowed is False
    assert result.reason == "IP not-an-ip not in global allowlist/blocklist"


def test_is_ip_allowed_signature_unchanged() -> None:
    import inspect

    sig = inspect.signature(is_ip_allowed)
    params = sig.parameters

    assert list(params) == [
        "ip",
        "config",
        "geo_ip_handler",
        "skip_ip_lists",
        "skip_countries",
    ]
    assert params["ip"].kind == inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert params["config"].kind == inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert params["geo_ip_handler"].default is None
    assert params["skip_ip_lists"].kind == inspect.Parameter.KEYWORD_ONLY
    assert params["skip_ip_lists"].default is False
    assert params["skip_countries"].kind == inspect.Parameter.KEYWORD_ONLY
    assert params["skip_countries"].default is False
    assert sig.return_annotation is bool


def test_is_ip_allowed_regression_bool_outcomes_by_block_type(
    mocker: MockerFixture,
) -> None:
    from guard_core.sync.handlers.cloud_handler import cloud_handler

    mocker.patch.object(
        cloud_handler, "is_cloud_ip", side_effect=lambda ip, *_: ip.startswith("13.")
    )
    cloud_config = SecurityConfig(block_cloud_providers={"AWS"})
    result = is_ip_allowed("13.59.255.255", cloud_config)
    assert result is True
    result = is_ip_allowed("8.8.8.8", cloud_config)
    assert result is True

    mock_ipinfo = MagicMock(spec=SyncGeoIPHandler)
    mock_ipinfo.get_country.return_value = "RU"
    country_config = SecurityConfig(
        blocked_countries=["RU"], geo_ip_handler=mock_ipinfo
    )
    result = is_ip_allowed("8.8.8.8", country_config, mock_ipinfo)
    assert result is False
    mock_ipinfo.get_country.return_value = "US"
    result = is_ip_allowed("8.8.8.8", country_config, mock_ipinfo)
    assert result is True

    blacklist_config = SecurityConfig(blacklist=["192.168.1.1"])
    result = is_ip_allowed("192.168.1.1", blacklist_config)
    assert result is False
    result = is_ip_allowed("10.0.0.1", blacklist_config)
    assert result is True


def test_check_ip_country_not_initialized() -> None:
    mock_ipinfo = MagicMock(spec=SyncGeoIPHandler)
    mock_ipinfo.is_initialized = False
    mock_ipinfo.initialize = MagicMock()
    mock_ipinfo.get_country.return_value = "US"

    config = SecurityConfig(
        blocked_countries=["CN"],
        geo_ip_handler=mock_ipinfo,
    )

    result = check_ip_country("1.1.1.1", config, mock_ipinfo)
    assert not result
    mock_ipinfo.initialize.assert_called_once()


def test_check_ip_country_no_country_found(
    security_config: SecurityConfig,
) -> None:
    mock_ipinfo = Mock()
    mock_ipinfo.reader = True
    mock_ipinfo.get_country.return_value = None

    result = check_ip_country("1.1.1.1", security_config, mock_ipinfo)
    assert not result


def test_check_ip_country_regression_returns_false_when_country_unresolvable(
    security_config: SecurityConfig,
) -> None:
    mock_ipinfo = Mock()
    mock_ipinfo.is_initialized = True
    mock_ipinfo.get_country.return_value = None

    security_config.geo_ip_handler = mock_ipinfo
    security_config.blocked_countries = frozenset({"CN"})

    result = check_ip_country("1.1.1.1", security_config, mock_ipinfo)

    assert result is False


def test_check_ip_country_no_countries_configured(
    caplog: Any,
) -> None:
    config = SecurityConfig(blocked_countries=[], whitelist_countries=[])

    mock_ipinfo = Mock()
    mock_ipinfo.reader = True
    mock_ipinfo.get_country.return_value = "US"

    with caplog.at_level(logging.DEBUG, logger="guard_core"):
        result = check_ip_country("1.1.1.1", config, mock_ipinfo)
        assert not result
        assert "No countries blocked or whitelisted" in caplog.text
        assert "1.1.1.1" in caplog.text


def test_is_ip_allowed_cidr_blacklist() -> None:
    config = SecurityConfig(blacklist=["192.168.1.0/24"], whitelist=[])

    assert not is_ip_allowed("192.168.1.100", config)
    assert not is_ip_allowed("192.168.1.1", config)
    assert not is_ip_allowed("192.168.1.254", config)

    assert is_ip_allowed("192.168.2.1", config)
    assert is_ip_allowed("192.168.0.1", config)
    assert is_ip_allowed("10.0.0.1", config)

    config_multiple = SecurityConfig(
        blacklist=["192.168.1.0/24", "10.0.0.0/8"],
        whitelist=[],
    )

    assert not is_ip_allowed("192.168.1.100", config_multiple)
    assert not is_ip_allowed("10.10.10.10", config_multiple)
    assert is_ip_allowed("172.16.0.1", config_multiple)


def test_is_ip_allowed_cidr_whitelist() -> None:
    config = SecurityConfig(whitelist=["192.168.1.0/24"], blacklist=[])

    assert is_ip_allowed("192.168.1.100", config)
    assert is_ip_allowed("192.168.1.1", config)
    assert is_ip_allowed("192.168.1.254", config)

    assert not is_ip_allowed("192.168.2.1", config)
    assert not is_ip_allowed("192.168.0.1", config)
    assert not is_ip_allowed("10.0.0.1", config)

    config_multiple = SecurityConfig(
        whitelist=["192.168.1.0/24", "10.0.0.0/8"],
        blacklist=[],
    )

    assert is_ip_allowed("192.168.1.100", config_multiple)
    assert is_ip_allowed("10.10.10.10", config_multiple)
    assert not is_ip_allowed("172.16.0.1", config_multiple)


def test_is_ip_allowed_invalid_ip(caplog: Any) -> None:
    config = SecurityConfig()

    with caplog.at_level(logging.ERROR):
        result = is_ip_allowed("invalid-ip", config)
        assert not result


def test_is_ip_allowed_general_exception(caplog: Any, mocker: MockerFixture) -> None:
    config = SecurityConfig()

    mock_error = Exception("Unexpected error")
    mocker.patch(
        "guard_core.sync._utils.access_control.ip_address", side_effect=mock_error
    )

    with caplog.at_level(logging.ERROR):
        result = is_ip_allowed("192.168.1.1", config)
        assert result
        assert "Error checking IP 192.168.1.1" in caplog.text
        assert "Unexpected error" in caplog.text


def test_detect_penetration_attempt_body_error() -> None:
    mock_request = Mock()
    mock_request.client_host = "127.0.0.1"
    mock_request.query_params = {}
    mock_request.url_path = "/"
    mock_request.headers = {"content-type": "application/json", "content-length": "10"}
    mock_request.body = MagicMock(side_effect=Exception("Body read error"))

    _dpa = detect_penetration_attempt(mock_request)

    result = _dpa.is_threat
    assert not result


def test_is_ip_allowed_blocked_country(mocker: MockerFixture) -> None:
    config = SecurityConfig(
        blocked_countries=["CN"], geo_ip_handler=MagicMock(spec=SyncGeoIPHandler)
    )

    mock_ipinfo = Mock()
    mock_ipinfo.reader = True
    mock_ipinfo.get_country.return_value = "CN"

    mocker.patch("guard_core.sync.utils.check_ip_country", return_value=True)

    result = is_ip_allowed("192.168.1.1", config, mock_ipinfo)
    assert not result


def test_detect_penetration_attempt_regex_timeout() -> None:
    from tests.test_sync.conftest import SyncMockGuardRequest

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
        query_params={"param": "test"},
        body_content=b"",
    )

    def mock_detect_with_timeout(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "is_threat": False,
            "threat_score": 0.0,
            "threats": [],
            "context": kwargs.get("context", "unknown"),
            "original_length": len(kwargs.get("content", "")),
            "processed_length": len(kwargs.get("content", "")),
            "execution_time": 2.1,
            "detection_method": "enhanced",
            "timeouts": ["test_pattern"],
            "correlation_id": kwargs.get("correlation_id"),
        }

    with (
        patch.object(
            sus_patterns_handler, "detect", side_effect=mock_detect_with_timeout
        ),
        patch("logging.getLogger") as mock_get_logger,
    ):
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger

        _dpa = detect_penetration_attempt(request)

        result, trigger = _dpa.is_threat, _dpa.trigger_info

        assert not result
        assert trigger == ""


def test_detect_penetration_attempt_regex_exception() -> None:
    from tests.test_sync.conftest import SyncMockGuardRequest

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
        query_params={"param": "test"},
        body_content=b"",
    )

    def mock_detect_with_exception(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise Exception("Unexpected detection error")

    with (
        patch.object(
            sus_patterns_handler, "detect", side_effect=mock_detect_with_exception
        ),
        patch("logging.Logger.error") as mock_error,
    ):
        _dpa = detect_penetration_attempt(request)

        result, trigger = _dpa.is_threat, _dpa.trigger_info

        assert not result
        assert trigger == ""

        mock_error.assert_called()
        error_msg = mock_error.call_args[0][0]
        assert "Enhanced detection failed" in error_msg


def test_detect_penetration_json_non_regex_threat() -> None:
    from tests.test_sync.conftest import SyncMockGuardRequest

    json_payload = '{"username": "admin", "password": "test_password"}'

    request = SyncMockGuardRequest(
        path="/api/login",
        method="POST",
        headers={},
        client_host="127.0.0.1",
        query_params={"data": json_payload},
        body_content=b"",
    )

    def mock_detect(*args: Any, **kwargs: Any) -> dict[str, Any]:
        content = args[0] if args else kwargs.get("content", "")
        if "test_password" in content:
            return {
                "is_threat": True,
                "threats": [{"type": "semantic", "attack_type": "credential_stuffing"}],
            }
        return {"is_threat": False, "threats": []}

    with patch.object(sus_patterns_handler, "detect", side_effect=mock_detect):
        _dpa = detect_penetration_attempt(request)

        result, trigger = _dpa.is_threat, _dpa.trigger_info

        assert result is True
        assert (
            "Request body field 'password': Semantic attack: credential_stuffing"
            in (trigger)
        )


def test_detect_penetration_semantic_threat() -> None:
    from tests.test_sync.conftest import SyncMockGuardRequest

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
        query_params={"search": "SELECT * FROM users WHERE admin=1"},
        body_content=b"",
    )

    def mock_detect(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "is_threat": True,
            "threats": [
                {
                    "type": "semantic",
                    "attack_type": "sql_injection",
                    "probability": 0.95,
                }
            ],
        }

    with patch.object(sus_patterns_handler, "detect", side_effect=mock_detect):
        _dpa = detect_penetration_attempt(request)

        result, trigger = _dpa.is_threat, _dpa.trigger_info

        assert result is True
        assert "Semantic attack: sql_injection (score: 0.95)" in trigger


def test_detect_penetration_semantic_threat_with_score() -> None:
    from tests.test_sync.conftest import SyncMockGuardRequest

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
        query_params={"input": "malicious_content"},
        body_content=b"",
    )

    def mock_detect(*args: Any, **kwargs: Any) -> dict[str, Any]:
        return {
            "is_threat": True,
            "threats": [
                {"type": "semantic", "attack_type": "suspicious", "threat_score": 0.88}
            ],
        }

    with patch.object(sus_patterns_handler, "detect", side_effect=mock_detect):
        _dpa = detect_penetration_attempt(request)

        result, trigger = _dpa.is_threat, _dpa.trigger_info

        assert result is True
        assert "Semantic attack: suspicious (score: 0.88)" in trigger


def test_detect_penetration_fallback_pattern_match() -> None:
    from tests.test_sync.conftest import SyncMockGuardRequest

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
        query_params={"test": "<script>alert(1)</script>"},
        body_content=b"",
    )

    def mock_detect_error(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("Detection engine failure")

    mock_pattern = re.compile(r"<script>")

    _all_ctx = frozenset(
        {"query_param", "header", "url_path", "request_body", "unknown"}
    )
    with (
        patch.object(sus_patterns_handler, "detect", side_effect=mock_detect_error),
        patch.object(
            sus_patterns_handler,
            "get_all_compiled_patterns",
            return_value=[(mock_pattern, _all_ctx, "custom")],
        ),
        patch("logging.Logger.error") as mock_error,
    ):
        _dpa = detect_penetration_attempt(request)

        result, trigger = _dpa.is_threat, _dpa.trigger_info

        assert result is True
        assert "Value matched pattern (fallback)" in trigger

        mock_error.assert_called()
        error_msg = mock_error.call_args[0][0]
        assert "Enhanced detection failed" in error_msg


def test_detect_penetration_fallback_pattern_exception() -> None:
    from tests.test_sync.conftest import SyncMockGuardRequest

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
        query_params={"test": "normal_content"},
        body_content=b"",
    )

    def mock_detect_error(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("Detection engine failure")

    mock_pattern = re.compile(r"unmatched_pattern_xyz")

    _all_ctx = frozenset(
        {"query_param", "header", "url_path", "request_body", "unknown"}
    )
    with (
        patch.object(sus_patterns_handler, "detect", side_effect=mock_detect_error),
        patch.object(
            sus_patterns_handler,
            "get_all_compiled_patterns",
            return_value=[(mock_pattern, _all_ctx, "custom")],
        ),
        patch.object(
            sus_patterns_handler,
            "_check_regex_pattern",
            side_effect=RecursionError("Pattern error"),
        ),
        patch("logging.Logger.error") as mock_log_error,
    ):
        _dpa = detect_penetration_attempt(request)

        result, trigger = _dpa.is_threat, _dpa.trigger_info

        assert result is False
        assert trigger == ""

        assert mock_log_error.call_count >= 1
        for call in mock_log_error.call_args_list:
            assert "Enhanced detection failed" in call[0][0]
            assert "Detection engine failure" in call[0][0]


def test_detect_penetration_short_body() -> None:
    from tests.test_sync.conftest import SyncMockGuardRequest

    short_body = b"<script>XSS</script>"

    request = SyncMockGuardRequest(
        path="/submit",
        method="POST",
        headers={},
        client_host="127.0.0.1",
        query_params={},
        body_content=short_body,
    )

    with patch("logging.Logger.warning") as mock_warning:
        _dpa = detect_penetration_attempt(request)

        result, trigger = _dpa.is_threat, _dpa.trigger_info

        assert result is True
        assert "Request body:" in trigger

        warning_calls = mock_warning.call_args_list
        body_logged = False
        for call in warning_calls:
            if "<script>XSS</script>" in str(call):
                body_logged = True
                break
        assert body_logged


def test_detect_penetration_empty_threat_fallback() -> None:
    from tests.test_sync.conftest import SyncMockGuardRequest

    json_payload = '{"field": "suspicious_value"}'

    request = SyncMockGuardRequest(
        path="/api/data",
        method="POST",
        headers={},
        client_host="127.0.0.1",
        query_params={"data": json_payload},
        body_content=b"",
    )

    def mock_detect(*args: Any, **kwargs: Any) -> dict[str, Any]:
        if kwargs.get("content") == "suspicious_value":
            return {
                "is_threat": True,
                "threats": [],
            }
        return {"is_threat": False, "threats": []}

    with patch.object(sus_patterns_handler, "detect", side_effect=mock_detect):
        _dpa = detect_penetration_attempt(request)

        result, trigger = _dpa.is_threat, _dpa.trigger_info

        assert result is True
        assert "Request body field 'field': Threat detected" in trigger


def test_detect_penetration_unknown_threat_type() -> None:
    from tests.test_sync.conftest import SyncMockGuardRequest

    request = SyncMockGuardRequest(
        path="/",
        method="GET",
        headers={},
        client_host="127.0.0.1",
        query_params={"param": "test_value"},
        body_content=b"",
    )

    def mock_detect(*_args: Any, **kwargs: Any) -> dict[str, Any]:
        if kwargs.get("content") == "test_value":
            return {
                "is_threat": True,
                "threats": [{"type": "unknown_type", "data": "some_data"}],
            }
        return {"is_threat": False, "threats": []}

    with patch.object(sus_patterns_handler, "detect", side_effect=mock_detect):
        _dpa = detect_penetration_attempt(request)

        result, trigger = _dpa.is_threat, _dpa.trigger_info

        assert result is True
        assert trigger == "Query param 'param': Threat detected"
