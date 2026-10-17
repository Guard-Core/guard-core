import logging
from collections.abc import Callable, Generator
from typing import Any, cast
from unittest.mock import MagicMock

import pytest

from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.behavioral.context import BehavioralContext
from guard_core.sync.core.behavioral.processor import BehavioralProcessor
from guard_core.sync.core.bypass.context import BypassContext
from guard_core.sync.core.bypass.handler import BypassHandler
from guard_core.sync.core.checks.factory import build_default_pipeline
from guard_core.sync.core.routing.context import RoutingContext
from guard_core.sync.core.routing.resolver import RouteConfigResolver
from guard_core.sync.core.validation.context import ValidationContext
from guard_core.sync.core.validation.validator import RequestValidator
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from guard_core.sync.handlers.ratelimit_handler import rate_limit_handler
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from tests.test_sync.conftest import MockGuardResponse, SyncMockGuardRequest

_LOGGER = logging.getLogger("test_exclusion_scope_contract")


def _config(**overrides: Any) -> SecurityConfig:
    fields: dict[str, Any] = {"enable_redis": False, "exclude_paths": ["/healthz"]}
    fields.update(overrides)
    return SecurityConfig(**fields)


def _build_middleware(config: SecurityConfig) -> MagicMock:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = _LOGGER
    middleware.event_bus = MagicMock()
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(
        side_effect=lambda status_code, default_message: MockGuardResponse(
            default_message, status_code
        )
    )
    middleware.guard_decorator = None
    middleware.route_resolver = RouteConfigResolver(
        RoutingContext(config=config, logger=_LOGGER, guard_decorator=None)
    )
    middleware.geo_ip_handler = None
    middleware.agent_handler = None
    middleware.rate_limit_handler = rate_limit_handler(config)
    middleware.suspicious_request_counts = {}
    return middleware


def _build_bypass_handler(
    config: SecurityConfig, middleware: MagicMock
) -> BypassHandler:
    validator = RequestValidator(
        ValidationContext(config=config, logger=_LOGGER, event_bus=middleware.event_bus)
    )
    response_factory = MagicMock()
    response_factory.apply_modifier = MagicMock(side_effect=lambda r: r)
    return BypassHandler(
        BypassContext(
            config=config,
            logger=_LOGGER,
            event_bus=middleware.event_bus,
            route_resolver=middleware.route_resolver,
            response_factory=response_factory,
            validator=validator,
        )
    )


def _never_called(request: SyncGuardRequest) -> GuardResponse:
    raise AssertionError("call_next must not run before the security pipeline")


@pytest.fixture(autouse=True)
def _reset_shared_handlers() -> Generator[None, None, None]:
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.banned_networks.clear()
    rate_limit_handler(SecurityConfig()).request_timestamps.clear()
    yield
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.banned_networks.clear()
    rate_limit_handler(SecurityConfig()).request_timestamps.clear()


def test_banned_ip_is_blocked_on_excluded_path_end_to_end() -> None:
    client_ip = "203.0.113.5"
    config = _config(enable_ip_banning=True)
    middleware = _build_middleware(config)
    bypass_handler = _build_bypass_handler(config, middleware)
    pipeline = build_default_pipeline(middleware)

    ip_ban_manager.ban_ip(client_ip, 300, "pre_existing_ban")

    request = SyncMockGuardRequest(path="/healthz", client_host=client_ip)

    passthrough = bypass_handler.handle_passthrough(
        request, cast(Callable[[SyncGuardRequest], GuardResponse], _never_called)
    )
    assert passthrough is None
    assert request.state.guard_exclusion_scoped is True

    result = pipeline.execute(request)

    assert result is not None
    assert result.status_code == 403


def test_non_banned_ip_on_excluded_path_passes_through() -> None:
    config = _config(enable_ip_banning=True)
    middleware = _build_middleware(config)
    pipeline = build_default_pipeline(middleware)

    request = SyncMockGuardRequest(path="/healthz", client_host="203.0.113.55")
    request.state.guard_exclusion_scoped = True

    result = pipeline.execute(request)

    assert result is None


def test_rate_limit_is_enforced_on_excluded_path() -> None:
    config = _config(enable_rate_limiting=True, rate_limit=1, rate_limit_window=60)
    config.rate_limit = 0
    middleware = _build_middleware(config)
    pipeline = build_default_pipeline(middleware)

    request = SyncMockGuardRequest(path="/healthz", client_host="203.0.113.6")
    request.state.guard_exclusion_scoped = True

    result = pipeline.execute(request)

    assert result is not None
    assert result.status_code == 429


def test_detection_does_not_run_on_excluded_path() -> None:
    client_ip = "203.0.113.7"
    config = _config(
        enable_penetration_detection=True,
        enable_ip_banning=True,
        auto_ban_threshold=1,
        auto_ban_duration=300,
    )
    middleware = _build_middleware(config)
    pipeline = build_default_pipeline(middleware)

    excluded_request = SyncMockGuardRequest(
        path="/healthz",
        client_host=client_ip,
        query_params={"q": "' OR '1'='1"},
    )
    excluded_request.state.guard_exclusion_scoped = True

    excluded_result = pipeline.execute(excluded_request)

    assert excluded_result is None
    assert middleware.suspicious_request_counts == {}
    assert ip_ban_manager.is_ip_banned(client_ip) is False

    control_request = SyncMockGuardRequest(
        path="/other",
        client_host=client_ip,
        query_params={"q": "' OR '1'='1"},
    )
    control_result = pipeline.execute(control_request)

    assert control_result is not None
    assert control_result.status_code == 403
    assert ip_ban_manager.is_ip_banned(client_ip) is True


def test_excluded_path_does_not_feed_behavioral_sample_collection() -> None:
    client_ip = "203.0.113.8"
    config = _config(enable_ip_banning=True)
    tracker = BehaviorTracker(config)
    event_bus = MagicMock()
    event_bus.send_middleware_event = MagicMock()
    processor = BehavioralProcessor(
        BehavioralContext(
            config=config,
            logger=_LOGGER,
            event_bus=event_bus,
            guard_decorator=None,
            behavior_tracker=tracker,
        )
    )
    rule = BehaviorRule(
        rule_type="frequency", threshold=0, window=60, action="ban", ban_duration=300
    )
    route_config = RouteConfig()
    route_config.behavior_rules = [rule]

    request = SyncMockGuardRequest(path="/healthz", client_host=client_ip)
    request.state.guard_exclusion_scoped = True

    processor.process_usage_rules(request, client_ip, route_config)

    assert tracker.usage_counts == {}


def test_excluded_path_can_never_trigger_a_behavioral_auto_ban() -> None:
    client_ip = "203.0.113.9"
    config = _config(enable_ip_banning=True)
    tracker = BehaviorTracker(config)
    event_bus = MagicMock()
    event_bus.send_middleware_event = MagicMock()
    processor = BehavioralProcessor(
        BehavioralContext(
            config=config,
            logger=_LOGGER,
            event_bus=event_bus,
            guard_decorator=None,
            behavior_tracker=tracker,
        )
    )
    rule = BehaviorRule(
        rule_type="frequency", threshold=0, window=60, action="ban", ban_duration=300
    )
    route_config = RouteConfig()
    route_config.behavior_rules = [rule]

    request = SyncMockGuardRequest(path="/healthz", client_host=client_ip)
    request.state.guard_exclusion_scoped = True

    for _ in range(25):
        processor.process_usage_rules(request, client_ip, route_config)

    assert ip_ban_manager.is_ip_banned(client_ip) is False

    control_request = SyncMockGuardRequest(path="/other", client_host=client_ip)
    processor.process_usage_rules(control_request, client_ip, route_config)

    assert ip_ban_manager.is_ip_banned(client_ip) is True


def test_non_excluded_request_behaviour_is_unchanged() -> None:
    client_ip = "203.0.113.10"
    config = _config(
        enable_ip_banning=True,
        enable_rate_limiting=True,
        rate_limit=100,
        rate_limit_window=60,
        enable_penetration_detection=True,
    )
    middleware = _build_middleware(config)
    pipeline = build_default_pipeline(middleware)

    request = SyncMockGuardRequest(path="/other", client_host=client_ip)

    assert getattr(request.state, "guard_exclusion_scoped", False) is not True

    result = pipeline.execute(request)

    assert result is None

    ip_ban_manager.ban_ip(client_ip, 300, "pre_existing_ban")
    banned_request = SyncMockGuardRequest(path="/other", client_host=client_ip)
    banned_result = pipeline.execute(banned_request)

    assert banned_result is not None
    assert banned_result.status_code == 403


def test_passive_mode_still_only_logs_a_banned_ip_on_excluded_path() -> None:
    client_ip = "203.0.113.11"
    config = _config(enable_ip_banning=True, passive_mode=True)
    middleware = _build_middleware(config)
    pipeline = build_default_pipeline(middleware)

    ip_ban_manager.ban_ip(client_ip, 300, "pre_existing_ban")

    request = SyncMockGuardRequest(path="/healthz", client_host=client_ip)
    request.state.guard_exclusion_scoped = True

    result = pipeline.execute(request)

    assert result is None


def test_static_blacklisted_ip_is_blocked_on_excluded_path_end_to_end() -> None:
    blacklisted_ip = "198.51.100.20"
    config = _config(blacklist=[blacklisted_ip])
    middleware = _build_middleware(config)
    pipeline = build_default_pipeline(middleware)

    normal_request = SyncMockGuardRequest(path="/other", client_host=blacklisted_ip)
    normal_result = pipeline.execute(normal_request)

    assert normal_result is not None
    assert normal_result.status_code == 403

    excluded_request = SyncMockGuardRequest(path="/healthz", client_host=blacklisted_ip)
    excluded_request.state.guard_exclusion_scoped = True
    excluded_result = pipeline.execute(excluded_request)

    assert excluded_result is not None
    assert excluded_result.status_code == 403


def test_static_blacklist_block_on_excluded_path_does_not_run_detection() -> None:
    blacklisted_ip = "198.51.100.21"
    config = _config(
        blacklist=[blacklisted_ip],
        enable_penetration_detection=True,
        enable_ip_banning=True,
        auto_ban_threshold=1,
        auto_ban_duration=300,
    )
    middleware = _build_middleware(config)
    pipeline = build_default_pipeline(middleware)

    request = SyncMockGuardRequest(
        path="/healthz",
        client_host=blacklisted_ip,
        query_params={"q": "' OR '1'='1"},
    )
    request.state.guard_exclusion_scoped = True

    result = pipeline.execute(request)

    assert result is not None
    assert result.status_code == 403
    assert middleware.suspicious_request_counts == {}
    assert ip_ban_manager.is_ip_banned(blacklisted_ip) is False


def test_globally_whitelisted_ip_still_passes_through_excluded_path() -> None:
    whitelisted_ip = "198.51.100.22"
    config = _config(whitelist=[whitelisted_ip])
    middleware = _build_middleware(config)
    pipeline = build_default_pipeline(middleware)

    request = SyncMockGuardRequest(path="/healthz", client_host=whitelisted_ip)
    request.state.guard_exclusion_scoped = True

    result = pipeline.execute(request)

    assert result is None


def test_non_blacklisted_ip_still_passes_through_excluded_path() -> None:
    config = _config(blacklist=["198.51.100.99"])
    middleware = _build_middleware(config)
    pipeline = build_default_pipeline(middleware)

    request = SyncMockGuardRequest(path="/healthz", client_host="198.51.100.23")
    request.state.guard_exclusion_scoped = True

    result = pipeline.execute(request)

    assert result is None


def test_blocked_country_is_enforced_on_excluded_path() -> None:
    client_ip = "198.51.100.24"
    config = _config()
    config.geo_ip_handler = MagicMock()
    config.blocked_countries = frozenset({"CN"})
    middleware = _build_middleware(config)
    middleware.geo_ip_handler = MagicMock()
    middleware.geo_ip_handler.get_country.return_value = "CN"
    pipeline = build_default_pipeline(middleware)

    request = SyncMockGuardRequest(path="/healthz", client_host=client_ip)
    request.state.guard_exclusion_scoped = True

    result = pipeline.execute(request)

    assert result is not None
    assert result.status_code == 403


def test_passive_mode_only_logs_a_globally_blocked_ip_on_excluded_path() -> None:
    blacklisted_ip = "198.51.100.25"
    config = _config(blacklist=[blacklisted_ip], passive_mode=True)
    middleware = _build_middleware(config)
    pipeline = build_default_pipeline(middleware)

    request = SyncMockGuardRequest(path="/healthz", client_host=blacklisted_ip)
    request.state.guard_exclusion_scoped = True

    result = pipeline.execute(request)

    assert result is None
