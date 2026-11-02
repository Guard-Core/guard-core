import importlib.util
from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guard_core.sync.core.checks.base import SecurityCheck
    from guard_core.sync.core.checks.factory import (
        DEFAULT_CHECK_CLASSES,
        build_default_pipeline,
    )
    from guard_core.sync.core.checks.implementations import (
        AuthenticationCheck,
        CloudIpRefreshCheck,
        CloudProviderCheck,
        CorsPreflightCheck,
        CustomRequestCheck,
        CustomValidatorsCheck,
        EmergencyModeCheck,
        HttpsEnforcementCheck,
        IpSecurityCheck,
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
    from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline

__all__ = [
    "SecurityCheck",
    "SecurityCheckPipeline",
    "DEFAULT_CHECK_CLASSES",
    "build_default_pipeline",
    "RouteConfigCheck",
    "EmergencyModeCheck",
    "HttpsEnforcementCheck",
    "RequestLoggingCheck",
    "RequestSizeContentCheck",
    "RequiredHeadersCheck",
    "AuthenticationCheck",
    "ReferrerCheck",
    "CustomValidatorsCheck",
    "TimeWindowCheck",
    "CloudIpRefreshCheck",
    "IpSecurityCheck",
    "CloudProviderCheck",
    "CorsPreflightCheck",
    "UserAgentCheck",
    "RateLimitCheck",
    "SuspiciousActivityCheck",
    "CustomRequestCheck",
]

# each name maps to its module, relative to this package
_MODULE_BY_NAME: dict[str, str] = {
    "SecurityCheck": "base",
    "SecurityCheckPipeline": "pipeline",
    "DEFAULT_CHECK_CLASSES": "factory",
    "build_default_pipeline": "factory",
    "RouteConfigCheck": "implementations.route_config",
    "EmergencyModeCheck": "implementations.emergency_mode",
    "HttpsEnforcementCheck": "implementations.https_enforcement",
    "RequestLoggingCheck": "implementations.request_logging",
    "RequestSizeContentCheck": "implementations.request_size_content",
    "RequiredHeadersCheck": "implementations.required_headers",
    "AuthenticationCheck": "implementations.authentication",
    "ReferrerCheck": "implementations.referrer",
    "CustomValidatorsCheck": "implementations.custom_validators",
    "TimeWindowCheck": "implementations.time_window",
    "CloudIpRefreshCheck": "implementations.cloud_ip_refresh",
    "IpSecurityCheck": "implementations.ip_security",
    "CloudProviderCheck": "implementations.cloud_provider",
    "CorsPreflightCheck": "implementations.cors_preflight",
    "UserAgentCheck": "implementations.user_agent",
    "RateLimitCheck": "implementations.rate_limit",
    "SuspiciousActivityCheck": "implementations.suspicious_activity",
    "CustomRequestCheck": "implementations.custom_request",
}


def __getattr__(name: str) -> object:
    module_name = _MODULE_BY_NAME.get(name)
    if module_name is not None:
        value = getattr(import_module(f"{__name__}.{module_name}"), name)
        globals()[name] = value
        return value

    submodule_name = f"{__name__}.{name}"
    if importlib.util.find_spec(submodule_name) is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    submodule = import_module(submodule_name)
    globals()[name] = submodule
    return submodule


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
