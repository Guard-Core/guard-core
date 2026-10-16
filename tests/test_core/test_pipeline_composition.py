from collections.abc import Collection

from guard_core.core.checks import build_default_pipeline
from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.implementations import RouteConfigCheck
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from tests.test_core.conftest import (
    custom_check,
    fully_enabled_route_config,
    middleware_for,
)


def test_default_config_builds_minimal_pipeline() -> None:
    middleware = middleware_for(SecurityConfig(), route_configs=())
    pipeline = build_default_pipeline(middleware)

    assert pipeline.get_check_names() == [
        "route_config",
        "ip_security",
        "rate_limit",
        "suspicious_activity",
    ]


def test_fully_enabled_config_builds_all_checks_in_canonical_order() -> None:
    config = SecurityConfig(
        emergency_mode=True,
        enforce_https=True,
        log_request_level="INFO",
        block_cloud_providers={"AWS"},
        blocked_user_agents=["badbot"],
        custom_request_check=custom_check,
    )
    middleware = middleware_for(config, route_configs=(fully_enabled_route_config(),))
    pipeline = build_default_pipeline(middleware)

    assert pipeline.get_check_names() == [
        "route_config",
        "emergency_mode",
        "https_enforcement",
        "request_logging",
        "request_size_content",
        "cloud_ip_refresh",
        "ip_security",
        "cloud_provider",
        "user_agent",
        "rate_limit",
        "required_headers",
        "authentication",
        "referrer",
        "custom_validators",
        "time_window",
        "suspicious_activity",
        "custom_request",
    ]


def test_enable_dynamic_rules_keeps_mutable_checks_with_every_flag_off() -> None:
    config = SecurityConfig(
        enable_dynamic_rules=True,
        enable_agent=True,
        agent_api_key="test-key",
        enable_ip_banning=False,
        enable_rate_limiting=False,
        enable_penetration_detection=False,
    )
    middleware = middleware_for(config, route_configs=())
    pipeline = build_default_pipeline(middleware)

    assert pipeline.get_check_names() == [
        "route_config",
        "emergency_mode",
        "cloud_ip_refresh",
        "ip_security",
        "cloud_provider",
        "user_agent",
        "rate_limit",
        "suspicious_activity",
    ]


def test_unknown_route_configs_keeps_every_route_driven_check() -> None:
    middleware = middleware_for(SecurityConfig(), route_configs=None)
    pipeline = build_default_pipeline(middleware)

    assert pipeline.get_check_names() == [
        "route_config",
        "https_enforcement",
        "request_size_content",
        "cloud_ip_refresh",
        "ip_security",
        "cloud_provider",
        "user_agent",
        "rate_limit",
        "required_headers",
        "authentication",
        "referrer",
        "custom_validators",
        "time_window",
        "suspicious_activity",
    ]


class _AlwaysDroppedCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "always_dropped"

    async def check(self, request: GuardRequest) -> GuardResponse | None:
        return None

    @classmethod
    def applies_to(
        cls,
        config: SecurityConfig,
        route_configs: Collection[RouteConfig] | None,
    ) -> bool:
        return False


def test_applies_to_false_excludes_check_from_pipeline() -> None:
    config = SecurityConfig()
    route_configs: tuple[RouteConfig, ...] = ()
    middleware = middleware_for(config, route_configs=route_configs)
    check_classes: tuple[type[SecurityCheck], ...] = (
        RouteConfigCheck,
        _AlwaysDroppedCheck,
    )

    checks = [
        cls(middleware)
        for cls in check_classes
        if cls.applies_to(config, route_configs)
    ]
    pipeline = SecurityCheckPipeline(checks, muted_check_logs=config.muted_check_logs)

    assert pipeline.get_check_names() == ["route_config"]
