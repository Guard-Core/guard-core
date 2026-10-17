from collections.abc import Collection

import pytest

from guard_core.core.checks import build_default_pipeline
from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.implementations import (
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
from guard_core.decorators.base import RouteConfig
from guard_core.handlers.behavior_handler import BehaviorRule
from guard_core.models import SecurityConfig
from tests.test_core.conftest import custom_check, custom_validator, middleware_for


def _route_config(**overrides: object) -> RouteConfig:
    route_config = RouteConfig()
    for name, value in overrides.items():
        setattr(route_config, name, value)
    return route_config


CONFIG_DRIVEN_CASES = [
    pytest.param(
        EmergencyModeCheck,
        SecurityConfig(emergency_mode=True),
        (),
        True,
        id="emergency_mode-keep",
    ),
    pytest.param(
        EmergencyModeCheck,
        SecurityConfig(),
        (),
        False,
        id="emergency_mode-drop",
    ),
    pytest.param(
        HttpsEnforcementCheck,
        SecurityConfig(enforce_https=True),
        (),
        True,
        id="https_enforcement-keep",
    ),
    pytest.param(
        HttpsEnforcementCheck,
        SecurityConfig(),
        (),
        False,
        id="https_enforcement-drop",
    ),
    pytest.param(
        RequestLoggingCheck,
        SecurityConfig(log_request_level="INFO"),
        (),
        True,
        id="request_logging-keep",
    ),
    pytest.param(
        RequestLoggingCheck,
        SecurityConfig(),
        (),
        False,
        id="request_logging-drop",
    ),
    pytest.param(
        CloudIpRefreshCheck,
        SecurityConfig(block_cloud_providers={"AWS"}),
        (),
        True,
        id="cloud_ip_refresh-keep",
    ),
    pytest.param(
        CloudIpRefreshCheck,
        SecurityConfig(),
        (),
        False,
        id="cloud_ip_refresh-drop",
    ),
    pytest.param(
        CloudProviderCheck,
        SecurityConfig(block_cloud_providers={"AWS"}),
        (),
        True,
        id="cloud_provider-keep",
    ),
    pytest.param(
        CloudProviderCheck,
        SecurityConfig(),
        (),
        False,
        id="cloud_provider-drop",
    ),
    pytest.param(
        UserAgentCheck,
        SecurityConfig(blocked_user_agents=["badbot"]),
        (),
        True,
        id="user_agent-keep",
    ),
    pytest.param(
        UserAgentCheck,
        SecurityConfig(),
        (),
        False,
        id="user_agent-drop",
    ),
    pytest.param(
        CustomRequestCheck,
        SecurityConfig(custom_request_check=custom_check),
        (),
        True,
        id="custom_request-keep",
    ),
    pytest.param(
        CustomRequestCheck,
        SecurityConfig(),
        (),
        False,
        id="custom_request-drop",
    ),
    pytest.param(
        RateLimitCheck,
        SecurityConfig(
            enable_rate_limiting=False, endpoint_rate_limits={"/x": (5, 60)}
        ),
        (),
        True,
        id="rate_limit-keep",
    ),
    pytest.param(
        RateLimitCheck,
        SecurityConfig(enable_rate_limiting=False),
        (),
        False,
        id="rate_limit-drop",
    ),
    pytest.param(
        RateLimitCheck,
        SecurityConfig(enable_rate_limiting=False),
        (_route_config(rate_limit=5),),
        True,
        id="rate_limit-route-keep",
    ),
    pytest.param(
        RateLimitCheck,
        SecurityConfig(enable_rate_limiting=False),
        (RouteConfig(),),
        False,
        id="rate_limit-route-drop",
    ),
    pytest.param(
        SuspiciousActivityCheck,
        SecurityConfig(enable_penetration_detection=False),
        (RouteConfig(),),
        True,
        id="suspicious_activity-keep",
    ),
    pytest.param(
        SuspiciousActivityCheck,
        SecurityConfig(enable_penetration_detection=False),
        (),
        False,
        id="suspicious_activity-drop",
    ),
]


@pytest.mark.parametrize(
    "check_class, config, route_configs, expected", CONFIG_DRIVEN_CASES
)
def test_config_driven_check_applies_to_matches_predicate(
    check_class: type[SecurityCheck],
    config: SecurityConfig,
    route_configs: tuple[RouteConfig, ...],
    expected: bool,
) -> None:
    assert check_class.applies_to(config, route_configs) is expected


DYNAMIC_RULE_ESCAPE_CHECKS: tuple[type[SecurityCheck], ...] = (
    EmergencyModeCheck,
    CloudIpRefreshCheck,
    CloudProviderCheck,
    UserAgentCheck,
    RateLimitCheck,
    SuspiciousActivityCheck,
)


@pytest.mark.parametrize("check_class", DYNAMIC_RULE_ESCAPE_CHECKS)
def test_dynamic_rules_flag_forces_keep_regardless_of_other_flags(
    check_class: type[SecurityCheck],
) -> None:
    config = SecurityConfig(
        enable_dynamic_rules=True,
        enable_agent=True,
        agent_api_key="test-key",
        enable_ip_banning=False,
        enable_rate_limiting=False,
        enable_penetration_detection=False,
    )
    assert check_class.applies_to(config, ()) is True


ROUTE_DRIVEN_CASES = [
    pytest.param(
        RequestSizeContentCheck,
        (_route_config(max_request_size=1000),),
        True,
        id="request_size_content-keep",
    ),
    pytest.param(
        RequestSizeContentCheck,
        (RouteConfig(),),
        False,
        id="request_size_content-drop",
    ),
    pytest.param(
        RequestSizeContentCheck,
        None,
        True,
        id="request_size_content-none-keeps",
    ),
    pytest.param(
        RequiredHeadersCheck,
        (_route_config(required_headers={"X-Api-Key": "required"}),),
        True,
        id="required_headers-keep",
    ),
    pytest.param(
        RequiredHeadersCheck,
        (RouteConfig(),),
        False,
        id="required_headers-drop",
    ),
    pytest.param(
        RequiredHeadersCheck,
        None,
        True,
        id="required_headers-none-keeps",
    ),
    pytest.param(
        AuthenticationCheck,
        (_route_config(auth_required="bearer"),),
        True,
        id="authentication-keep",
    ),
    pytest.param(
        AuthenticationCheck,
        (RouteConfig(),),
        False,
        id="authentication-drop",
    ),
    pytest.param(
        AuthenticationCheck,
        None,
        True,
        id="authentication-none-keeps",
    ),
    pytest.param(
        ReferrerCheck,
        (_route_config(require_referrer=["example.com"]),),
        True,
        id="referrer-keep",
    ),
    pytest.param(
        ReferrerCheck,
        (RouteConfig(),),
        False,
        id="referrer-drop",
    ),
    pytest.param(
        ReferrerCheck,
        None,
        True,
        id="referrer-none-keeps",
    ),
    pytest.param(
        CustomValidatorsCheck,
        (_route_config(custom_validators=[custom_validator]),),
        True,
        id="custom_validators-keep",
    ),
    pytest.param(
        CustomValidatorsCheck,
        (RouteConfig(),),
        False,
        id="custom_validators-drop",
    ),
    pytest.param(
        CustomValidatorsCheck,
        None,
        True,
        id="custom_validators-none-keeps",
    ),
    pytest.param(
        TimeWindowCheck,
        (_route_config(time_restrictions={"start": "00:00", "end": "23:59"}),),
        True,
        id="time_window-keep",
    ),
    pytest.param(
        TimeWindowCheck,
        (RouteConfig(),),
        False,
        id="time_window-drop",
    ),
    pytest.param(
        TimeWindowCheck,
        None,
        True,
        id="time_window-none-keeps",
    ),
    pytest.param(
        CloudIpRefreshCheck,
        (_route_config(block_cloud_providers={"AWS"}),),
        True,
        id="cloud_ip_refresh-route-keep",
    ),
    pytest.param(
        CloudIpRefreshCheck,
        (RouteConfig(),),
        False,
        id="cloud_ip_refresh-route-drop",
    ),
    pytest.param(
        CloudIpRefreshCheck,
        None,
        True,
        id="cloud_ip_refresh-none-keeps",
    ),
    pytest.param(
        CloudProviderCheck,
        (_route_config(block_cloud_providers={"AWS"}),),
        True,
        id="cloud_provider-route-keep",
    ),
    pytest.param(
        CloudProviderCheck,
        (RouteConfig(),),
        False,
        id="cloud_provider-route-drop",
    ),
    pytest.param(
        CloudProviderCheck,
        None,
        True,
        id="cloud_provider-none-keeps",
    ),
]


@pytest.mark.parametrize("check_class, route_configs, expected", ROUTE_DRIVEN_CASES)
def test_route_driven_check_applies_to_matches_predicate(
    check_class: type[SecurityCheck],
    route_configs: Collection[RouteConfig] | None,
    expected: bool,
) -> None:
    assert check_class.applies_to(SecurityConfig(), route_configs) is expected


def test_ip_security_survives_when_only_behaviour_rules_can_ban() -> None:
    config = SecurityConfig(enable_ip_banning=False, enable_dynamic_rules=False)
    route_config = _route_config(
        behavior_rules=[BehaviorRule(rule_type="usage", threshold=5, action="ban")]
    )
    middleware = middleware_for(config, route_configs=(route_config,))

    pipeline = build_default_pipeline(middleware)

    assert "ip_security" in pipeline.get_check_names()
