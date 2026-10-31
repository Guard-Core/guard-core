import importlib.util
from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guard_core.sync.core.checks.implementations.authentication import (
        AuthenticationCheck,
    )
    from guard_core.sync.core.checks.implementations.cloud_ip_refresh import (
        CloudIpRefreshCheck,
    )
    from guard_core.sync.core.checks.implementations.cloud_provider import (
        CloudProviderCheck,
    )
    from guard_core.sync.core.checks.implementations.cors_preflight import (
        CorsPreflightCheck,
    )
    from guard_core.sync.core.checks.implementations.custom_request import (
        CustomRequestCheck,
    )
    from guard_core.sync.core.checks.implementations.custom_validators import (
        CustomValidatorsCheck,
    )
    from guard_core.sync.core.checks.implementations.emergency_mode import (
        EmergencyModeCheck,
    )
    from guard_core.sync.core.checks.implementations.https_enforcement import (
        HttpsEnforcementCheck,
    )
    from guard_core.sync.core.checks.implementations.ip_security import IpSecurityCheck
    from guard_core.sync.core.checks.implementations.rate_limit import RateLimitCheck
    from guard_core.sync.core.checks.implementations.referrer import ReferrerCheck
    from guard_core.sync.core.checks.implementations.request_logging import (
        RequestLoggingCheck,
    )
    from guard_core.sync.core.checks.implementations.request_size_content import (
        RequestSizeContentCheck,
    )
    from guard_core.sync.core.checks.implementations.required_headers import (
        RequiredHeadersCheck,
    )
    from guard_core.sync.core.checks.implementations.route_config import (
        RouteConfigCheck,
    )
    from guard_core.sync.core.checks.implementations.suspicious_activity import (
        SuspiciousActivityCheck,
    )
    from guard_core.sync.core.checks.implementations.time_window import TimeWindowCheck
    from guard_core.sync.core.checks.implementations.user_agent import UserAgentCheck

__all__ = [
    "AuthenticationCheck",
    "CloudIpRefreshCheck",
    "CloudProviderCheck",
    "CorsPreflightCheck",
    "CustomRequestCheck",
    "CustomValidatorsCheck",
    "EmergencyModeCheck",
    "HttpsEnforcementCheck",
    "IpSecurityCheck",
    "RateLimitCheck",
    "ReferrerCheck",
    "RequestLoggingCheck",
    "RequestSizeContentCheck",
    "RequiredHeadersCheck",
    "RouteConfigCheck",
    "SuspiciousActivityCheck",
    "TimeWindowCheck",
    "UserAgentCheck",
]

# each name maps to its module, relative to this package
_MODULE_BY_NAME: dict[str, str] = {
    "AuthenticationCheck": "authentication",
    "CloudIpRefreshCheck": "cloud_ip_refresh",
    "CloudProviderCheck": "cloud_provider",
    "CorsPreflightCheck": "cors_preflight",
    "CustomRequestCheck": "custom_request",
    "CustomValidatorsCheck": "custom_validators",
    "EmergencyModeCheck": "emergency_mode",
    "HttpsEnforcementCheck": "https_enforcement",
    "IpSecurityCheck": "ip_security",
    "RateLimitCheck": "rate_limit",
    "ReferrerCheck": "referrer",
    "RequestLoggingCheck": "request_logging",
    "RequestSizeContentCheck": "request_size_content",
    "RequiredHeadersCheck": "required_headers",
    "RouteConfigCheck": "route_config",
    "SuspiciousActivityCheck": "suspicious_activity",
    "TimeWindowCheck": "time_window",
    "UserAgentCheck": "user_agent",
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
