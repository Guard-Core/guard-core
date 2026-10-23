import logging
from collections.abc import Sequence
from ipaddress import ip_network
from itertools import product
from unittest.mock import MagicMock

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.implementations import (
    AuthenticationCheck,
    CloudIpRefreshCheck,
    CloudProviderCheck,
    CustomRequestCheck,
    CustomValidatorsCheck,
    EmergencyModeCheck,
    HttpsEnforcementCheck,
    RateLimitCheck,
    ReferrerCheck,
    RequestLoggingCheck,
    RequestSizeContentCheck,
    RequiredHeadersCheck,
    RouteConfigCheck,
    SuspiciousActivityCheck,
    TimeWindowCheck,
    UserAgentCheck,
)
from guard_core.sync.core.routing.context import RoutingContext
from guard_core.sync.core.routing.resolver import RouteConfigResolver
from guard_core.sync.decorators.base import BaseSecurityDecorator, RouteConfig
from guard_core.sync.handlers.cloud_handler import cloud_handler
from guard_core.sync.handlers.ratelimit_handler import rate_limit_handler
from tests.test_sync.conftest import MockGuardResponse, SyncMockGuardRequest

_LOGGER = logging.getLogger("test_applies_to_false_means_check_cannot_block")


def _blocking_custom_request_check(request: object) -> MockGuardResponse:
    return MockGuardResponse("blocked-by-custom-request-check", 451)


def _blocking_custom_validator(request: object) -> MockGuardResponse:
    return MockGuardResponse("blocked-by-custom-validator", 418)


def _neutral_config(**overrides: object) -> SyncSecurityConfig:
    fields: dict[str, object] = {
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
    }
    fields.update(overrides)
    if fields.get("enable_dynamic_rules"):
        fields.setdefault("enable_agent", True)
        fields.setdefault("agent_api_key", "test-key")
    return SyncSecurityConfig(**fields)


def _route_config(**overrides: object) -> RouteConfig:
    route_config = RouteConfig()
    for name, value in overrides.items():
        setattr(route_config, name, value)
    return route_config


def _build_middleware(
    config: SyncSecurityConfig, decorator: BaseSecurityDecorator
) -> MagicMock:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = _LOGGER
    middleware.event_bus = MagicMock()
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.event_bus.send_https_violation_event = MagicMock()
    middleware.event_bus.send_cloud_detection_events = MagicMock()
    middleware.create_error_response = MagicMock(
        side_effect=lambda status_code, default_message: MockGuardResponse(
            default_message, status_code
        )
    )
    middleware.response_factory = MagicMock()
    middleware.response_factory.apply_modifier = MagicMock(side_effect=lambda r: r)
    middleware.response_factory.create_https_redirect = MagicMock(
        return_value=MockGuardResponse("redirect", 301, {"Location": "https://test/"})
    )
    middleware.guard_decorator = decorator
    middleware.route_resolver = RouteConfigResolver(
        RoutingContext(config=config, logger=_LOGGER, guard_decorator=decorator)
    )
    middleware.geo_ip_handler = None
    middleware.agent_handler = None
    middleware.rate_limit_handler = rate_limit_handler(config)
    middleware.suspicious_request_counts = {}
    middleware.last_cloud_ip_refresh = 0
    middleware.refresh_cloud_ip_ranges = MagicMock()
    return middleware


def _assert_eliminated_check_cannot_block(
    check_class: type[SecurityCheck],
    config: SyncSecurityConfig,
    route_configs: tuple[RouteConfig, ...],
    route_id: str | None,
    adversarial_requests: Sequence[SyncMockGuardRequest],
) -> None:
    assert check_class.applies_to(config, route_configs) is False, (
        f"{check_class.__name__}: corpus row mislabels its own applies_to() as False"
    )

    decorator = BaseSecurityDecorator(config)
    decorator._route_configs = {
        f"route-{index}": route_config
        for index, route_config in enumerate(route_configs)
    }
    middleware = _build_middleware(config, decorator)
    route_config_check = RouteConfigCheck(middleware)
    check_under_test = check_class(middleware)

    for request in adversarial_requests:
        if route_id is not None:
            request.state.guard_route_id = route_id
        route_config_check.check(request)
        result = check_under_test.check(request)
        assert result is None, (
            f"{check_class.__name__}.check() blocked a request while "
            f"applies_to() said the check could never fire: {result!r}"
        )


_BOOL_AXIS = (False, True)


def test_emergency_mode_cannot_block_once_eliminated() -> None:
    for emergency_mode, enable_dynamic_rules in product(_BOOL_AXIS, _BOOL_AXIS):
        config = _neutral_config(
            emergency_mode=emergency_mode,
            emergency_whitelist=[],
            enable_dynamic_rules=enable_dynamic_rules,
        )
        if EmergencyModeCheck.applies_to(config, ()) is False:
            _assert_eliminated_check_cannot_block(
                EmergencyModeCheck,
                config,
                (),
                None,
                [SyncMockGuardRequest(client_host="203.0.113.10")],
            )


def test_https_enforcement_cannot_block_once_eliminated() -> None:
    for enforce_https, route_require_https in product(_BOOL_AXIS, _BOOL_AXIS):
        config = _neutral_config(enforce_https=enforce_https)
        route_configs = (_route_config(require_https=route_require_https),)
        if HttpsEnforcementCheck.applies_to(config, route_configs) is False:
            _assert_eliminated_check_cannot_block(
                HttpsEnforcementCheck,
                config,
                route_configs,
                "route-0",
                [SyncMockGuardRequest(client_host="203.0.113.11", scheme="http")],
            )


def test_request_logging_cannot_block_once_eliminated() -> None:
    for log_request_level in (None, "INFO"):
        config = _neutral_config(log_request_level=log_request_level)
        if RequestLoggingCheck.applies_to(config, ()) is False:
            _assert_eliminated_check_cannot_block(
                RequestLoggingCheck,
                config,
                (),
                None,
                [SyncMockGuardRequest(client_host="203.0.113.12")],
            )


def test_custom_request_cannot_block_once_eliminated() -> None:
    for custom_request_check in (None, _blocking_custom_request_check):
        config = _neutral_config(custom_request_check=custom_request_check)
        if CustomRequestCheck.applies_to(config, ()) is False:
            _assert_eliminated_check_cannot_block(
                CustomRequestCheck,
                config,
                (),
                None,
                [SyncMockGuardRequest(client_host="203.0.113.13")],
            )


def test_request_size_content_cannot_block_once_eliminated() -> None:
    for max_request_size, allowed_content_types in product(
        (None, 100), (None, ["text/html"])
    ):
        config = _neutral_config()
        route_configs = (
            _route_config(
                max_request_size=max_request_size,
                allowed_content_types=allowed_content_types,
            ),
        )
        if RequestSizeContentCheck.applies_to(config, route_configs) is False:
            _assert_eliminated_check_cannot_block(
                RequestSizeContentCheck,
                config,
                route_configs,
                "route-0",
                [
                    SyncMockGuardRequest(
                        client_host="203.0.113.14",
                        headers={
                            "content-length": "999999",
                            "content-type": "application/xml",
                        },
                    )
                ],
            )


def test_required_headers_cannot_block_once_eliminated() -> None:
    for required_headers in ({}, {"X-Api-Key": "required"}):
        config = _neutral_config()
        route_configs = (_route_config(required_headers=required_headers),)
        if RequiredHeadersCheck.applies_to(config, route_configs) is False:
            _assert_eliminated_check_cannot_block(
                RequiredHeadersCheck,
                config,
                route_configs,
                "route-0",
                [SyncMockGuardRequest(client_host="203.0.113.15", headers={})],
            )


def test_authentication_cannot_block_once_eliminated() -> None:
    for auth_required in (None,):
        config = _neutral_config()
        route_configs = (_route_config(auth_required=auth_required),)
        if AuthenticationCheck.applies_to(config, route_configs) is False:
            _assert_eliminated_check_cannot_block(
                AuthenticationCheck,
                config,
                route_configs,
                "route-0",
                [SyncMockGuardRequest(client_host="203.0.113.16", headers={})],
            )


def test_referrer_cannot_block_once_eliminated() -> None:
    for require_referrer in (None, ["example.com"]):
        config = _neutral_config()
        route_configs = (_route_config(require_referrer=require_referrer),)
        if ReferrerCheck.applies_to(config, route_configs) is False:
            _assert_eliminated_check_cannot_block(
                ReferrerCheck,
                config,
                route_configs,
                "route-0",
                [
                    SyncMockGuardRequest(
                        client_host="203.0.113.17",
                        headers={"referer": "https://evil.example/"},
                    ),
                    SyncMockGuardRequest(client_host="203.0.113.17", headers={}),
                ],
            )


def test_custom_validators_cannot_block_once_eliminated() -> None:
    for custom_validators in ([], [_blocking_custom_validator]):
        config = _neutral_config()
        route_configs = (_route_config(custom_validators=custom_validators),)
        if CustomValidatorsCheck.applies_to(config, route_configs) is False:
            _assert_eliminated_check_cannot_block(
                CustomValidatorsCheck,
                config,
                route_configs,
                "route-0",
                [SyncMockGuardRequest(client_host="203.0.113.18")],
            )


def test_time_window_cannot_block_once_eliminated() -> None:
    for time_restrictions in (
        None,
        {"start": "00:00", "end": "00:01", "timezone": "UTC"},
    ):
        config = _neutral_config()
        route_configs = (_route_config(time_restrictions=time_restrictions),)
        if TimeWindowCheck.applies_to(config, route_configs) is False:
            _assert_eliminated_check_cannot_block(
                TimeWindowCheck,
                config,
                route_configs,
                "route-0",
                [SyncMockGuardRequest(client_host="203.0.113.19")],
            )


def _cloud_axis_combinations() -> list[
    tuple[SyncSecurityConfig, tuple[RouteConfig, ...]]
]:
    combos: list[tuple[SyncSecurityConfig, tuple[RouteConfig, ...]]] = []
    for config_blocks, enable_dynamic_rules, route_blocks in product(
        (set(), {"AWS"}), _BOOL_AXIS, (set(), {"AWS"})
    ):
        config = _neutral_config(
            block_cloud_providers=config_blocks,
            enable_dynamic_rules=enable_dynamic_rules,
        )
        route_configs = (_route_config(block_cloud_providers=route_blocks),)
        combos.append((config, route_configs))
    return combos


def test_cloud_ip_refresh_cannot_block_once_eliminated() -> None:
    cloud_handler.ip_ranges["AWS"].add(ip_network("3.0.0.0/8"))
    for config, route_configs in _cloud_axis_combinations():
        if CloudIpRefreshCheck.applies_to(config, route_configs) is False:
            _assert_eliminated_check_cannot_block(
                CloudIpRefreshCheck,
                config,
                route_configs,
                "route-0",
                [SyncMockGuardRequest(client_host="3.0.0.9")],
            )


def test_cloud_provider_cannot_block_once_eliminated() -> None:
    cloud_handler.ip_ranges["AWS"].add(ip_network("3.0.0.0/8"))
    for config, route_configs in _cloud_axis_combinations():
        if CloudProviderCheck.applies_to(config, route_configs) is False:
            _assert_eliminated_check_cannot_block(
                CloudProviderCheck,
                config,
                route_configs,
                "route-0",
                [SyncMockGuardRequest(client_host="3.0.0.9")],
            )


def test_user_agent_cannot_block_once_eliminated() -> None:
    for config_blocked, route_blocked, enable_dynamic_rules in product(
        ([], ["badbot"]), ([], ["badbot"]), _BOOL_AXIS
    ):
        config = _neutral_config(
            blocked_user_agents=config_blocked,
            enable_dynamic_rules=enable_dynamic_rules,
        )
        route_configs = (_route_config(blocked_user_agents=route_blocked),)
        if UserAgentCheck.applies_to(config, route_configs) is False:
            _assert_eliminated_check_cannot_block(
                UserAgentCheck,
                config,
                route_configs,
                "route-0",
                [
                    SyncMockGuardRequest(
                        client_host="203.0.113.20",
                        headers={"User-Agent": "badbot-scanner"},
                    )
                ],
            )


def test_rate_limit_cannot_block_once_eliminated() -> None:
    for (
        enable_rate_limiting,
        endpoint_rate_limits,
        route_rate_limit,
        route_geo_rate_limits,
        enable_dynamic_rules,
    ) in product(
        _BOOL_AXIS,
        ({}, {"/x": (1, 60)}),
        (None, 0),
        (None, {"*": (0, 60)}),
        _BOOL_AXIS,
    ):
        config = _neutral_config(
            enable_rate_limiting=enable_rate_limiting,
            endpoint_rate_limits=endpoint_rate_limits,
            enable_dynamic_rules=enable_dynamic_rules,
        )
        route_configs = (
            _route_config(
                rate_limit=route_rate_limit,
                geo_rate_limits=route_geo_rate_limits,
            ),
        )
        if RateLimitCheck.applies_to(config, route_configs) is False:
            _assert_eliminated_check_cannot_block(
                RateLimitCheck,
                config,
                route_configs,
                "route-0",
                [SyncMockGuardRequest(client_host="203.0.113.21")],
            )


def test_suspicious_activity_cannot_block_once_eliminated() -> None:
    for (
        enable_penetration_detection,
        route_enable_suspicious_detection,
        enable_dynamic_rules,
    ) in product(_BOOL_AXIS, _BOOL_AXIS, _BOOL_AXIS):
        config = _neutral_config(
            enable_penetration_detection=enable_penetration_detection,
            enable_dynamic_rules=enable_dynamic_rules,
        )
        route_configs = (
            _route_config(
                enable_suspicious_detection=route_enable_suspicious_detection
            ),
        )
        if SuspiciousActivityCheck.applies_to(config, route_configs) is False:
            _assert_eliminated_check_cannot_block(
                SuspiciousActivityCheck,
                config,
                route_configs,
                "route-0",
                [
                    SyncMockGuardRequest(
                        client_host="203.0.113.30",
                        query_params={"q": "' OR '1'='1"},
                    )
                ],
            )
