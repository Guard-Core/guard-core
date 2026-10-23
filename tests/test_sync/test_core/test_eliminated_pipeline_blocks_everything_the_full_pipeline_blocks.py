import logging
from collections.abc import Callable
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass
from ipaddress import ip_network
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.factory import (
    DEFAULT_CHECK_CLASSES,
    build_default_pipeline,
)
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
    SuspiciousActivityCheck,
    TimeWindowCheck,
    UserAgentCheck,
)
from guard_core.sync.core.routing.context import RoutingContext
from guard_core.sync.core.routing.resolver import RouteConfigResolver
from guard_core.sync.decorators.base import BaseSecurityDecorator, RouteConfig
from guard_core.sync.handlers.cloud_handler import cloud_handler
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from guard_core.sync.handlers.ratelimit_handler import rate_limit_handler
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from tests.test_sync.conftest import MockGuardResponse, SyncMockGuardRequest

_LOGGER = logging.getLogger("test_eliminated_pipeline_parity")


def _neutral_config(**overrides: object) -> SyncSecurityConfig:
    fields: dict[str, object] = {
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
    }
    fields.update(overrides)
    return SyncSecurityConfig(**fields)


def _always_limited_config() -> SyncSecurityConfig:
    config = _neutral_config(
        enable_rate_limiting=True, rate_limit=1, rate_limit_window=60
    )
    config.rate_limit = 0
    return config


def _route_config(**overrides: object) -> RouteConfig:
    route_config = RouteConfig()
    for name, value in overrides.items():
        setattr(route_config, name, value)
    return route_config


def _blocking_custom_request_check(request: object) -> GuardResponse:
    return MockGuardResponse("blocked-by-custom-request-check", 451)


def _blocking_custom_validator(request: object) -> GuardResponse:
    return MockGuardResponse("blocked-by-custom-validator", 418)


@dataclass
class EliminationCase:
    id: str
    check_class: type[SecurityCheck]
    predicate_keeps: bool
    config: SyncSecurityConfig
    route_configs: tuple[RouteConfig, ...] | None
    request_route_id: str | None
    request_kwargs: dict[str, Any]
    setup: Callable[[], None] | None = None
    patcher: Callable[[], AbstractContextManager] | None = None
    expect_block: bool = False
    expect_check_name: str | None = None


CORPUS: list[EliminationCase] = [
    EliminationCase(
        id="emergency_mode-keep-blocks",
        check_class=EmergencyModeCheck,
        predicate_keeps=True,
        config=_neutral_config(emergency_mode=True, emergency_whitelist=[]),
        route_configs=None,
        request_route_id=None,
        request_kwargs={"client_host": "198.51.100.5"},
        expect_block=True,
        expect_check_name="emergency_mode",
    ),
    EliminationCase(
        id="emergency_mode-drop-cannot-block",
        check_class=EmergencyModeCheck,
        predicate_keeps=False,
        config=_neutral_config(emergency_mode=False, enable_dynamic_rules=False),
        route_configs=None,
        request_route_id=None,
        request_kwargs={"client_host": "198.51.100.6"},
    ),
    EliminationCase(
        id="https_enforcement-keep-blocks",
        check_class=HttpsEnforcementCheck,
        predicate_keeps=True,
        config=_neutral_config(enforce_https=True),
        route_configs=None,
        request_route_id=None,
        request_kwargs={"client_host": "198.51.100.7", "scheme": "http"},
        expect_block=True,
        expect_check_name="https_enforcement",
    ),
    EliminationCase(
        id="https_enforcement-drop-cannot-block",
        check_class=HttpsEnforcementCheck,
        predicate_keeps=False,
        config=_neutral_config(enforce_https=False),
        route_configs=(_route_config(),),
        request_route_id=None,
        request_kwargs={"client_host": "198.51.100.7", "scheme": "http"},
    ),
    EliminationCase(
        id="request_logging-keep-cannot-block",
        check_class=RequestLoggingCheck,
        predicate_keeps=True,
        config=_neutral_config(log_request_level="INFO"),
        route_configs=None,
        request_route_id=None,
        request_kwargs={"client_host": "198.51.100.9"},
    ),
    EliminationCase(
        id="request_logging-drop-cannot-block",
        check_class=RequestLoggingCheck,
        predicate_keeps=False,
        config=_neutral_config(log_request_level=None),
        route_configs=None,
        request_route_id=None,
        request_kwargs={"client_host": "198.51.100.9"},
    ),
    EliminationCase(
        id="cloud_ip_refresh-keep-cannot-block",
        check_class=CloudIpRefreshCheck,
        predicate_keeps=True,
        config=_neutral_config(),
        route_configs=(_route_config(block_cloud_providers={"AWS"}),),
        request_route_id="route-0",
        request_kwargs={"client_host": "198.51.100.8"},
    ),
    EliminationCase(
        id="cloud_ip_refresh-drop-external-cloud-state-cannot-block",
        check_class=CloudIpRefreshCheck,
        predicate_keeps=False,
        config=_neutral_config(),
        route_configs=(_route_config(),),
        request_route_id=None,
        request_kwargs={"client_host": "198.51.100.8"},
        setup=lambda: cloud_handler.ip_ranges["AWS"].add(ip_network("3.0.0.0/8")),
    ),
    EliminationCase(
        id="cloud_provider-keep-blocks",
        check_class=CloudProviderCheck,
        predicate_keeps=True,
        config=_neutral_config(),
        route_configs=(_route_config(block_cloud_providers={"AWS"}),),
        request_route_id="route-0",
        request_kwargs={"client_host": "3.0.0.9"},
        setup=lambda: cloud_handler.ip_ranges["AWS"].add(ip_network("3.0.0.0/8")),
        expect_block=True,
        expect_check_name="cloud_provider",
    ),
    EliminationCase(
        id="cloud_provider-drop-external-cloud-state-cannot-block",
        check_class=CloudProviderCheck,
        predicate_keeps=False,
        config=_neutral_config(),
        route_configs=(_route_config(),),
        request_route_id=None,
        request_kwargs={"client_host": "3.0.0.9"},
        setup=lambda: cloud_handler.ip_ranges["AWS"].add(ip_network("3.0.0.0/8")),
    ),
    EliminationCase(
        id="custom_request-keep-blocks",
        check_class=CustomRequestCheck,
        predicate_keeps=True,
        config=_neutral_config(custom_request_check=_blocking_custom_request_check),
        route_configs=None,
        request_route_id=None,
        request_kwargs={"client_host": "198.51.100.11"},
        expect_block=True,
        expect_check_name="custom_request",
    ),
    EliminationCase(
        id="custom_request-drop-cannot-block",
        check_class=CustomRequestCheck,
        predicate_keeps=False,
        config=_neutral_config(custom_request_check=None),
        route_configs=None,
        request_route_id=None,
        request_kwargs={"client_host": "198.51.100.11"},
    ),
    EliminationCase(
        id="custom_validators-keep-blocks",
        check_class=CustomValidatorsCheck,
        predicate_keeps=True,
        config=_neutral_config(),
        route_configs=(_route_config(custom_validators=[_blocking_custom_validator]),),
        request_route_id="route-0",
        request_kwargs={"client_host": "198.51.100.12"},
        expect_block=True,
        expect_check_name="custom_validators",
    ),
    EliminationCase(
        id="custom_validators-drop-cannot-block",
        check_class=CustomValidatorsCheck,
        predicate_keeps=False,
        config=_neutral_config(),
        route_configs=(_route_config(),),
        request_route_id="route-0",
        request_kwargs={"client_host": "198.51.100.12"},
    ),
    EliminationCase(
        id="required_headers-keep-blocks",
        check_class=RequiredHeadersCheck,
        predicate_keeps=True,
        config=_neutral_config(),
        route_configs=(_route_config(required_headers={"X-Api-Key": "required"}),),
        request_route_id="route-0",
        request_kwargs={"client_host": "198.51.100.13"},
        expect_block=True,
        expect_check_name="required_headers",
    ),
    EliminationCase(
        id="required_headers-drop-cannot-block",
        check_class=RequiredHeadersCheck,
        predicate_keeps=False,
        config=_neutral_config(),
        route_configs=(_route_config(),),
        request_route_id="route-0",
        request_kwargs={"client_host": "198.51.100.13"},
    ),
    EliminationCase(
        id="authentication-keep-blocks",
        check_class=AuthenticationCheck,
        predicate_keeps=True,
        config=_neutral_config(),
        route_configs=(_route_config(auth_required="bearer"),),
        request_route_id="route-0",
        request_kwargs={"client_host": "198.51.100.14"},
        expect_block=True,
        expect_check_name="authentication",
    ),
    EliminationCase(
        id="authentication-drop-cannot-block",
        check_class=AuthenticationCheck,
        predicate_keeps=False,
        config=_neutral_config(),
        route_configs=(_route_config(),),
        request_route_id="route-0",
        request_kwargs={
            "client_host": "198.51.100.14",
            "headers": {"authorization": "Bearer irrelevant-token"},
        },
    ),
    EliminationCase(
        id="referrer-keep-blocks",
        check_class=ReferrerCheck,
        predicate_keeps=True,
        config=_neutral_config(),
        route_configs=(_route_config(require_referrer=["example.com"]),),
        request_route_id="route-0",
        request_kwargs={"client_host": "198.51.100.15"},
        expect_block=True,
        expect_check_name="referrer",
    ),
    EliminationCase(
        id="referrer-drop-cannot-block",
        check_class=ReferrerCheck,
        predicate_keeps=False,
        config=_neutral_config(),
        route_configs=(_route_config(),),
        request_route_id="route-0",
        request_kwargs={
            "client_host": "198.51.100.15",
            "headers": {"referer": "https://evil.example/"},
        },
    ),
    EliminationCase(
        id="time_window-keep-blocks",
        check_class=TimeWindowCheck,
        predicate_keeps=True,
        config=_neutral_config(),
        route_configs=(
            _route_config(
                time_restrictions={
                    "start": "00:00",
                    "end": "00:01",
                    "timezone": "UTC",
                }
            ),
        ),
        request_route_id="route-0",
        request_kwargs={"client_host": "198.51.100.16"},
        patcher=lambda: patch.object(
            TimeWindowCheck,
            "_check_time_window",
            MagicMock(return_value=False),
        ),
        expect_block=True,
        expect_check_name="time_window",
    ),
    EliminationCase(
        id="time_window-drop-cannot-block",
        check_class=TimeWindowCheck,
        predicate_keeps=False,
        config=_neutral_config(),
        route_configs=(_route_config(),),
        request_route_id="route-0",
        request_kwargs={"client_host": "198.51.100.16"},
    ),
    EliminationCase(
        id="request_size_content-keep-blocks",
        check_class=RequestSizeContentCheck,
        predicate_keeps=True,
        config=_neutral_config(),
        route_configs=(_route_config(max_request_size=100),),
        request_route_id="route-0",
        request_kwargs={
            "client_host": "198.51.100.17",
            "headers": {"content-length": "200"},
        },
        expect_block=True,
        expect_check_name="request_size_content",
    ),
    EliminationCase(
        id="request_size_content-drop-cannot-block",
        check_class=RequestSizeContentCheck,
        predicate_keeps=False,
        config=_neutral_config(),
        route_configs=(_route_config(),),
        request_route_id="route-0",
        request_kwargs={
            "client_host": "198.51.100.17",
            "headers": {"content-length": "99999", "content-type": "text/html"},
        },
    ),
    EliminationCase(
        id="user_agent-keep-blocks",
        check_class=UserAgentCheck,
        predicate_keeps=True,
        config=_neutral_config(blocked_user_agents=["badbot"]),
        route_configs=None,
        request_route_id=None,
        request_kwargs={
            "client_host": "198.51.100.18",
            "headers": {"User-Agent": "badbot-scanner"},
        },
        expect_block=True,
        expect_check_name="user_agent",
    ),
    EliminationCase(
        id="user_agent-drop-cannot-block",
        check_class=UserAgentCheck,
        predicate_keeps=False,
        config=_neutral_config(blocked_user_agents=[], enable_dynamic_rules=False),
        route_configs=(_route_config(),),
        request_route_id=None,
        request_kwargs={
            "client_host": "198.51.100.18",
            "headers": {"User-Agent": "badbot-scanner"},
        },
    ),
    EliminationCase(
        id="rate_limit-keep-blocks",
        check_class=RateLimitCheck,
        predicate_keeps=True,
        config=_always_limited_config(),
        route_configs=None,
        request_route_id=None,
        request_kwargs={"client_host": "198.51.100.20"},
        expect_block=True,
        expect_check_name="rate_limit",
    ),
    EliminationCase(
        id="rate_limit-drop-cannot-block",
        check_class=RateLimitCheck,
        predicate_keeps=False,
        config=_neutral_config(enable_rate_limiting=False, endpoint_rate_limits={}),
        route_configs=(_route_config(),),
        request_route_id=None,
        request_kwargs={"client_host": "198.51.100.21"},
    ),
    EliminationCase(
        id="suspicious_activity-keep-blocks-and-bans-via-ip_ban_manager",
        check_class=SuspiciousActivityCheck,
        predicate_keeps=True,
        config=_neutral_config(
            enable_penetration_detection=True,
            enable_ip_banning=True,
            auto_ban_threshold=1,
            auto_ban_duration=300,
        ),
        route_configs=None,
        request_route_id=None,
        request_kwargs={
            "client_host": "198.51.100.30",
            "query_params": {"q": "' OR '1'='1"},
        },
        expect_block=True,
        expect_check_name="suspicious_activity",
    ),
    EliminationCase(
        id="suspicious_activity-drop-real-sqli-payload-cannot-block",
        check_class=SuspiciousActivityCheck,
        predicate_keeps=False,
        config=_neutral_config(
            enable_penetration_detection=False, enable_dynamic_rules=False
        ),
        route_configs=(_route_config(enable_suspicious_detection=False),),
        request_route_id="route-0",
        request_kwargs={
            "client_host": "198.51.100.30",
            "query_params": {"q": "' OR '1'='1"},
        },
    ),
]


def _decorator_for(
    config: SyncSecurityConfig, route_configs: tuple[RouteConfig, ...] | None
) -> BaseSecurityDecorator | None:
    if route_configs is None:
        return None
    decorator = BaseSecurityDecorator(config)
    decorator._route_configs = {
        f"route-{index}": route_config
        for index, route_config in enumerate(route_configs)
    }
    return decorator


def _build_middleware(
    config: SyncSecurityConfig, decorator: BaseSecurityDecorator | None
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


def _reset_external_handlers() -> None:
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.banned_networks.clear()
    cloud_instance = cloud_handler._instance
    if cloud_instance is not None:
        cloud_instance.ip_ranges = {"AWS": set(), "GCP": set(), "Azure": set()}
    sus_patterns_handler.custom_patterns = set()
    sus_patterns_handler.compiled_custom_patterns = set()
    rate_limit_handler(SyncSecurityConfig()).request_timestamps.clear()


def _run_pipeline(
    checks: list[SecurityCheck], request: SyncMockGuardRequest
) -> tuple[int | None, str | None]:
    for check in checks:
        response = check.check(request)
        if response is not None:
            return response.status_code, check.check_name
    return None, None


def _run_side(
    case: EliminationCase, *, eliminated: bool
) -> tuple[int | None, str | None]:
    _reset_external_handlers()
    if case.setup is not None:
        case.setup()

    decorator = _decorator_for(case.config, case.route_configs)
    middleware = _build_middleware(case.config, decorator)

    if eliminated:
        checks = build_default_pipeline(middleware).checks
    else:
        checks = [cls(middleware) for cls in DEFAULT_CHECK_CLASSES]

    request = SyncMockGuardRequest(**case.request_kwargs)
    if case.request_route_id is not None:
        request.state.guard_route_id = case.request_route_id

    return _run_pipeline(checks, request)


@pytest.mark.parametrize("case", CORPUS, ids=[case.id for case in CORPUS])
def test_eliminated_pipeline_blocks_everything_the_full_pipeline_blocks(
    case: EliminationCase,
) -> None:
    assert case.check_class.applies_to(case.config, case.route_configs) is (
        case.predicate_keeps
    ), f"{case.id}: corpus case mislabels its own applies_to() expectation"

    context = case.patcher() if case.patcher is not None else nullcontext()
    with (
        patch.object(cloud_handler, "schedule_refresh", MagicMock(return_value=False)),
        context,
    ):
        reference_result = _run_side(case, eliminated=False)
        eliminated_result = _run_side(case, eliminated=True)

    assert eliminated_result == reference_result, (
        f"{case.id}: eliminated pipeline diverged from the unfiltered pipeline "
        f"(reference={reference_result}, eliminated={eliminated_result}); "
        f"{case.check_class.__name__}.applies_to() is narrower than its check()"
    )

    if case.expect_block:
        assert reference_result[1] == case.expect_check_name, (
            f"{case.id}: expected {case.expect_check_name!r} to block, "
            f"got {reference_result!r}"
        )
    else:
        assert reference_result == (None, None), (
            f"{case.id}: expected no check to block, got {reference_result!r}"
        )
