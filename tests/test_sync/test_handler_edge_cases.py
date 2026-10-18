import ipaddress
import json
import time
from collections import deque
from typing import Any
from unittest.mock import MagicMock, patch

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.cloud_handler import CloudManager
from guard_core.sync.handlers.ipban_handler import IPBanManager, reset_global_state
from guard_core.sync.handlers.ratelimit_handler import (
    RateLimitManager,
    RateLimitTier,
    RateLimitVerdict,
    _in_memory_tier_verdict,
)
from guard_core.sync.handlers.redis_handler import RedisManager
from guard_core.sync.handlers.security_headers_handler import SecurityHeadersManager
from tests.test_sync.conftest import (
    REDIS_URL,
    MockGuardResponse,
    MockGuardResponseFactory,
    SyncMockGuardRequest,
)


def test_ipban_in_memory_expired() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    mgr.banned_ips["1.2.3.4"] = time.time() - 100
    result = mgr.is_ip_banned("1.2.3.4")
    assert result is False


def test_ipban_in_memory_valid() -> None:
    IPBanManager._instance = None
    mgr = IPBanManager()
    mgr.banned_ips["1.2.3.4"] = time.time() + 1000
    result = mgr.is_ip_banned("1.2.3.4")
    assert result is True


def test_ipban_reset_global_state() -> None:
    IPBanManager._instance = None
    reset_global_state()
    from guard_core.sync.handlers import ipban_handler

    assert ipban_handler.ip_ban_manager is not None


def test_ratelimit_popleft_stale_timestamps() -> None:
    config = SecurityConfig(enable_redis=False)
    mgr = RateLimitManager(config)
    old_time = time.time() - 120
    current = time.time()
    mgr.request_timestamps["1.2.3.4"] = deque([old_time, old_time + 1])
    verdict = _in_memory_tier_verdict(
        mgr.request_timestamps, "1.2.3.4", [RateLimitTier("global", 1, 60)], current
    )
    assert verdict == RateLimitVerdict(None)
    assert list(mgr.request_timestamps["1.2.3.4"]) == [current]


def test_cloud_handler_get_details_match() -> None:
    handler = CloudManager()
    network = ipaddress.ip_network("10.0.0.0/8")
    handler.ip_ranges = {"AWS": {network}}
    result = handler.get_cloud_provider_details("10.1.2.3", {"AWS"})
    assert result is not None
    assert result[0] == "AWS"


def test_cloud_handler_get_details_no_match() -> None:
    handler = CloudManager()
    network = ipaddress.ip_network("10.0.0.0/8")
    handler.ip_ranges = {"AWS": {network}}
    result = handler.get_cloud_provider_details("192.168.1.1", {"AWS"})
    assert result is None


def test_redis_delete_pattern_with_keys() -> None:
    config = SecurityConfig(enable_redis=True, redis_url=REDIS_URL)
    mgr = RedisManager(config)
    mgr.initialize()
    mgr.set_key("test_dp", "key1", "value1")
    result = mgr.delete_pattern("test_dp:*")
    assert result is not None
    mgr.close()


def test_security_headers_get_headers_agent_event() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr.headers_cache.clear()
    agent = MagicMock()
    agent.send_event = MagicMock()
    mgr.agent_handler = agent
    with patch(
        "guard_core.sync.handlers.security_headers_handler.SecurityEvent", create=True
    ) as mock_event:
        mock_event.return_value = MagicMock()
        headers = mgr.get_headers("/api/test")
    assert isinstance(headers, dict)


def test_security_headers_wildcard_credentials_true() -> None:
    SecurityHeadersManager._instance = None
    mgr = SecurityHeadersManager()
    mgr.cors_config = {
        "origins": ["*"],
        "allow_credentials": True,
        "allow_methods": ["GET"],
        "allow_headers": ["*"],
    }
    result = mgr._is_wildcard_with_credentials(["*"])
    assert result is True


def test_responses_factory_cors_with_headers() -> None:
    from guard_core.sync.core.events.metrics import MetricsCollector
    from guard_core.sync.core.responses.context import ResponseContext
    from guard_core.sync.core.responses.factory import ErrorResponseFactory

    SecurityHeadersManager._instance = None
    sec_mgr = SecurityHeadersManager()
    sec_mgr._configure_cors(
        cors_origins=["https://example.com"],
        cors_allow_credentials=False,
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["*"],
    )

    config = SecurityConfig(
        enable_redis=False,
        security_headers={"enabled": True},
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
    )
    metrics = MagicMock(spec=MetricsCollector)
    metrics.collect_request_metrics = MagicMock()
    ctx = ResponseContext(
        config=config,
        logger=MagicMock(),
        metrics_collector=metrics,
        response_factory=MockGuardResponseFactory(),
    )
    factory = ErrorResponseFactory(ctx)
    resp = MockGuardResponse("ok", 200)
    cors_headers = sec_mgr.get_cors_headers("https://example.com")
    assert "Access-Control-Allow-Origin" in cors_headers
    result = factory.apply_cors_headers(resp, "https://example.com")
    assert result is not None


def test_utils_extract_ip_null_client_host() -> None:
    from guard_core.sync.utils import _extract_ip_from_request

    req = SyncMockGuardRequest(client_host=None)
    result = _extract_ip_from_request(req)
    assert result == "unknown"


def test_utils_log_country_check_no_geolocation() -> None:
    from guard_core.sync.utils import _log_country_check_result

    _log_country_check_result("1.2.3.4", None, "no_geolocation", MagicMock())


def test_utils_check_country_no_geolocation() -> None:
    from guard_core.sync.utils import check_ip_country

    config = MagicMock()
    config.blocked_countries = ["CN"]
    config.whitelist_countries = []
    geo = MagicMock()
    geo.is_initialized = True
    geo.get_country = MagicMock(return_value=None)
    result = check_ip_country(SyncMockGuardRequest(), config, geo)
    assert result is False


def test_utils_detect_penetration_json_field_threat() -> None:
    from guard_core.sync.utils import detect_penetration_attempt

    req = SyncMockGuardRequest(
        path="/api",
        headers={"content-type": "application/json"},
        body_content=b'{"name": "SELECT * FROM users"}',
        query_params={},
    )
    result = detect_penetration_attempt(req)
    assert isinstance(result.is_threat, bool)


def test_utils_detect_penetration_header_threat() -> None:
    from guard_core.sync.utils import detect_penetration_attempt

    req = SyncMockGuardRequest(
        path="/api",
        headers={"X-Custom": "<script>alert(1)</script>"},
        query_params={},
    )
    result = detect_penetration_attempt(req)
    assert isinstance(result.is_threat, bool)


def test_utils_check_embedded_json_regex_threat() -> None:
    from guard_core.sync.utils import _check_embedded_json

    mock_result = {
        "is_threat": True,
        "threats": [{"type": "regex", "pattern": "SELECT.*FROM"}],
    }
    with patch(
        "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_handler:
        mock_handler.detect = MagicMock(return_value=mock_result)
        result = _check_embedded_json(
            json.dumps({"name": "SELECT * FROM users"}),
            "body",
            "1.2.3.4",
            "corr-1",
            None,
            frozenset(),
            frozenset(),
            False,
        )
    assert result is not None
    detected, info, _threats, _log_override = result
    assert detected is True
    assert "matched pattern" in info


def test_utils_check_embedded_json_other_threat() -> None:
    from guard_core.sync.utils import _check_embedded_json

    mock_result = {
        "is_threat": True,
        "threats": [{"type": "heuristic"}],
    }

    def _detect_only_value(*_a: object, **kw: object) -> dict[str, object]:
        if kw.get("content") == "payload":
            return mock_result
        return {"is_threat": False, "threats": []}

    with patch(
        "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_handler:
        mock_handler.detect = MagicMock(side_effect=_detect_only_value)
        result = _check_embedded_json(
            json.dumps({"field": "payload"}),
            "body",
            "1.2.3.4",
            "corr-1",
            None,
            frozenset(),
            frozenset(),
            False,
        )
    assert result is not None
    detected, info, _threats, _log_override = result
    assert detected is True
    assert "Request body field 'field': Threat detected" in info


def test_utils_check_embedded_json_no_threats_list() -> None:
    from guard_core.sync.utils import _check_embedded_json

    mock_result = {"is_threat": True, "threats": []}

    def _detect_only_value(*_a: object, **kw: object) -> dict[str, object]:
        if kw.get("content") == "val":
            return mock_result
        return {"is_threat": False, "threats": []}

    with patch(
        "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_handler:
        mock_handler.detect = MagicMock(side_effect=_detect_only_value)
        result = _check_embedded_json(
            json.dumps({"field": "val"}),
            "body",
            "1.2.3.4",
            "corr-1",
            None,
            frozenset(),
            frozenset(),
            False,
        )
    assert result is not None
    detected, info, _threats, _log_override = result
    assert detected is True
    assert "Request body field 'field': Threat detected" in info


def test_utils_check_embedded_json_clean() -> None:
    from guard_core.sync.utils import _check_embedded_json

    mock_result = {"is_threat": False, "threats": []}
    with patch(
        "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
    ) as mock_handler:
        mock_handler.detect = MagicMock(return_value=mock_result)
        result = _check_embedded_json(
            json.dumps({"field": "safe"}),
            "body",
            "1.2.3.4",
            "corr-1",
            None,
            frozenset(),
            frozenset(),
            False,
        )
    assert result is not None
    detected, _info, _threats, log_override = result
    assert detected is False
    assert log_override is None


def test_utils_detect_header_threat() -> None:
    from guard_core.sync.utils import _check_request_component

    with patch(
        "guard_core.sync._utils.detection_scan._check_value_enhanced",
        return_value=(True, "XSS detected", [], None),
    ):
        detected, trigger, threats = _check_request_component(
            "<script>",
            "header:X-Evil",
            "header 'X-Evil'",
            "1.2.3.4",
            "corr-1",
            None,
            "WARNING",
        )
    assert detected is True
    assert threats == []


def test_utils_detect_penetration_header_match() -> None:
    from guard_core.sync.utils import detect_penetration_attempt

    mock_check = MagicMock()

    with (
        patch(
            "guard_core.sync._utils.body_content_scan._check_request_component",
            mock_check,
        ),
        patch(
            "guard_core.sync._utils.penetration_detection._check_request_component",
            mock_check,
        ),
    ):
        call_count = 0

        def side_effect(
            value: str,
            context: str,
            component_name: str,
            client_ip: str,
            correlation_id: str,
            enabled_categories: set[str] | None = None,
            log_level: str | None = "WARNING",
            scan_embedded_json: bool = True,
            content_preview: str | None = None,
            sensitive_body_fields: frozenset[str] = frozenset(),
            excluded_body_fields: frozenset[str] = frozenset(),
            json_redact_all: bool | None = None,
            sensitive_params: frozenset[str] = frozenset(),
        ) -> tuple[bool, str, list[dict]]:
            nonlocal call_count
            call_count += 1
            if "header" in context and "X-Evil" in context:
                return (
                    True,
                    "XSS detected",
                    [{"type": "regex", "category": "xss", "pattern": "x"}],
                )
            return False, "", []

        mock_check.side_effect = side_effect

        req = SyncMockGuardRequest(
            path="/safe",
            headers={"X-Evil": "<script>alert(1)</script>"},
            query_params={},
        )
        result = detect_penetration_attempt(req)
    assert result.is_threat is True
    assert "Header" in result.trigger_info


def test_security_headers_get_headers_agent_sends_event() -> None:
    from guard_core.sync.handlers.security_headers_handler import (
        security_headers_manager,
    )

    security_headers_manager.headers_cache.clear()
    agent = MagicMock()
    agent.send_event = MagicMock()
    original_agent = security_headers_manager.agent_handler
    security_headers_manager.agent_handler = agent
    try:
        with patch(
            "guard_core.sync.handlers.security_headers_handler.SecurityEvent",
            create=True,
        ) as mock_event_cls:
            mock_event_cls.return_value = MagicMock()
            security_headers_manager.get_headers("/agent/test/path")
        agent.send_event.assert_called_once()
    finally:
        security_headers_manager.agent_handler = original_agent


def test_security_headers_get_headers_cache_hit() -> None:
    from guard_core.sync.handlers.security_headers_handler import (
        security_headers_manager,
    )

    security_headers_manager.headers_cache.clear()
    first = security_headers_manager.get_headers("/cache/hit/test")
    assert isinstance(first, dict)
    second = security_headers_manager.get_headers("/cache/hit/test")
    assert second is first


def test_security_headers_is_wildcard_with_creds_true() -> None:
    from guard_core.sync.handlers.security_headers_handler import (
        security_headers_manager,
    )

    original_cors = security_headers_manager.cors_config
    security_headers_manager.cors_config = {
        "origins": ["*"],
        "allow_credentials": True,
    }
    try:
        result = security_headers_manager._is_wildcard_with_credentials(["*"])
        assert result is True
        cors_result = security_headers_manager.get_cors_headers("https://test.com")
        assert cors_result == {}
    finally:
        security_headers_manager.cors_config = original_cors


def test_security_headers_is_wildcard_no_creds() -> None:
    from guard_core.sync.handlers.security_headers_handler import (
        security_headers_manager,
    )

    original_cors = security_headers_manager.cors_config
    security_headers_manager.cors_config = {
        "origins": ["*"],
        "allow_credentials": False,
    }
    try:
        result = security_headers_manager._is_wildcard_with_credentials(["*"])
        assert result is False
    finally:
        security_headers_manager.cors_config = original_cors


def test_security_headers_is_wildcard_no_cors_config() -> None:
    from guard_core.sync.handlers.security_headers_handler import (
        security_headers_manager,
    )

    original_cors = security_headers_manager.cors_config
    security_headers_manager.cors_config = None
    try:
        result = security_headers_manager._is_wildcard_with_credentials(["*"])
        assert result is False
    finally:
        security_headers_manager.cors_config = original_cors


def test_responses_factory_cors_applies_headers() -> None:
    from guard_core.sync.core.events.metrics import MetricsCollector
    from guard_core.sync.core.responses.context import ResponseContext
    from guard_core.sync.core.responses.factory import ErrorResponseFactory

    config = SecurityConfig(
        enable_redis=False,
        security_headers={"enabled": True},
    )
    metrics = MagicMock(spec=MetricsCollector)
    metrics.collect_request_metrics = MagicMock()
    ctx = ResponseContext(
        config=config,
        logger=MagicMock(),
        metrics_collector=metrics,
        response_factory=MockGuardResponseFactory(),
    )
    factory = ErrorResponseFactory(ctx)
    with patch.object(
        factory.security_headers_manager,
        "get_cors_headers",
        MagicMock(return_value={"Access-Control-Allow-Origin": "*"}),
    ):
        resp = MockGuardResponse("ok", 200)
        result = factory.apply_cors_headers(resp, "https://example.com")
    assert "Access-Control-Allow-Origin" in result.headers


def test_get_cloud_provider_details_skips_provider_not_in_ranges() -> None:
    # Line 229-230 branch: provider NOT in self.ip_ranges, loop continues.
    from guard_core.sync.handlers.cloud_handler import CloudManager

    CloudManager._instance = None
    mgr = CloudManager()
    mgr.ip_ranges = {"AWS": set()}  # only AWS in ranges
    result = mgr.get_cloud_provider_details("1.2.3.4", providers={"AWS", "Unknown"})
    assert result is None


def test_ipban_manager_returns_existing_singleton() -> None:
    # Covers the __new__ False branch (instance already exists).
    from guard_core.sync.handlers.ipban_handler import IPBanManager

    first = IPBanManager()
    second = IPBanManager()
    assert first is second


def test_is_ip_banned_not_in_memory_and_no_redis() -> None:
    # 102->111 False, then 113-115 with no redis_handler, returns False.
    from guard_core.sync.handlers.ipban_handler import IPBanManager

    manager = IPBanManager()
    manager.banned_ips.clear()
    manager.redis_handler = None
    assert manager.is_ip_banned("99.99.99.99") is False


def test_is_ip_banned_redis_miss_returns_false() -> None:
    from guard_core.sync.handlers.ipban_handler import IPBanManager

    manager = IPBanManager()
    manager.banned_ips.clear()
    manager.redis_handler = MagicMock()
    manager.redis_handler.get_key = MagicMock(return_value=None)
    manager.redis_handler.delete = MagicMock()
    assert manager.is_ip_banned("99.99.99.99") is False


def test_is_ip_banned_redis_stale_expiry_cleanup() -> None:
    import time

    from guard_core.sync.handlers.ipban_handler import IPBanManager

    manager = IPBanManager()
    manager.banned_ips.clear()
    manager.redis_handler = MagicMock()
    # expiry in the past
    manager.redis_handler.get_key = MagicMock(return_value=str(time.time() - 3600))
    manager.redis_handler.delete = MagicMock()
    assert manager.is_ip_banned("1.2.3.4") is False
    manager.redis_handler.delete.assert_called()


def test_fetch_gcp_ignores_prefixes_lacking_both_ipv4_and_ipv6() -> None:
    # Covers elif-False: loop continues over a prefix dict with neither key.
    from guard_core.sync.handlers.cloud_handler import fetch_gcp_ip_ranges

    class _FakeSession:
        def __enter__(self) -> "_FakeSession":
            return self

        def __exit__(self, *_a: Any) -> None:
            return None

        def get(self, *_a: Any, **_kw: Any) -> MagicMock:
            response = MagicMock()
            response.raise_for_status = MagicMock()
            response.json = MagicMock(
                return_value={
                    "prefixes": [
                        {"other_key": "value"},
                        {"ipv4Prefix": "10.0.0.0/8"},
                    ]
                }
            )
            return response

    with patch(
        "guard_core.sync.handlers._cloud_provider_fetchers.requests.Session",
        _FakeSession,
    ):
        networks, _ = fetch_gcp_ip_ranges()

    assert len(networks) == 1


def test_ipban_reset_noop_when_no_redis_handler() -> None:
    # reset() with redis_handler=None: `if self.redis_handler:` False, exit.
    from guard_core.sync.handlers.ipban_handler import IPBanManager

    manager = IPBanManager()
    manager.banned_ips["1.2.3.4"] = 1.0
    manager.redis_handler = None
    manager.reset()
    assert len(manager.banned_ips) == 0
