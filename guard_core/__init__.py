import importlib.util
from importlib import import_module
from importlib.metadata import PackageNotFoundError, version
from typing import TYPE_CHECKING, Any

try:
    __version__ = version("guard-core")
except PackageNotFoundError:
    __version__ = "unknown"

if TYPE_CHECKING:
    from guard_core.decorators import RouteConfig, SecurityDecorator
    from guard_core.handlers.behavior_handler import BehaviorRule, BehaviorTracker
    from guard_core.handlers.cloud_handler import CloudManager, cloud_handler
    from guard_core.handlers.ipban_handler import IPBanManager, ip_ban_manager
    from guard_core.handlers.ipinfo_handler import IPInfoManager
    from guard_core.handlers.ratelimit_handler import (
        RateLimitManager,
        check_rate_limit_by_ip,
        rate_limit_handler,
    )
    from guard_core.handlers.redis_handler import RedisManager, redis_handler
    from guard_core.handlers.security_headers_handler import (
        SecurityHeadersManager,
        security_headers_manager,
    )
    from guard_core.handlers.suspatterns_handler import sus_patterns_handler
    from guard_core.models import SecurityConfig
    from guard_core.protocols.geo_ip_protocol import GeoIPHandler
    from guard_core.protocols.redis_protocol import RedisHandlerProtocol
    from guard_core.protocols.request_protocol import BoundedBodyReader, GuardRequest
    from guard_core.protocols.response_protocol import (
        BoundedResponseBodyReader,
        GuardResponse,
        GuardResponseFactory,
    )
    from guard_core.utils import check_ip_access, is_ip_allowed

__all__ = [
    "SecurityConfig",
    "SecurityDecorator",
    "RouteConfig",
    "BehaviorTracker",
    "BehaviorRule",
    "ip_ban_manager",
    "IPBanManager",
    "cloud_handler",
    "CloudManager",
    "IPInfoManager",
    "rate_limit_handler",
    "RateLimitManager",
    "redis_handler",
    "RedisManager",
    "security_headers_manager",
    "SecurityHeadersManager",
    "sus_patterns_handler",
    "BoundedBodyReader",
    "BoundedResponseBodyReader",
    "GeoIPHandler",
    "RedisHandlerProtocol",
    "GuardRequest",
    "GuardResponse",
    "GuardResponseFactory",
    "is_ip_allowed",
    "check_ip_access",
    "check_rate_limit_by_ip",
]

_MODULE_BY_NAME: dict[str, str] = {
    "SecurityConfig": "guard_core.models",
    "SecurityDecorator": "guard_core.decorators",
    "RouteConfig": "guard_core.decorators",
    "BehaviorTracker": "guard_core.handlers.behavior_handler",
    "BehaviorRule": "guard_core.handlers.behavior_handler",
    "ip_ban_manager": "guard_core.handlers.ipban_handler",
    "IPBanManager": "guard_core.handlers.ipban_handler",
    "cloud_handler": "guard_core.handlers.cloud_handler",
    "CloudManager": "guard_core.handlers.cloud_handler",
    "IPInfoManager": "guard_core.handlers.ipinfo_handler",
    "rate_limit_handler": "guard_core.handlers.ratelimit_handler",
    "RateLimitManager": "guard_core.handlers.ratelimit_handler",
    "redis_handler": "guard_core.handlers.redis_handler",
    "RedisManager": "guard_core.handlers.redis_handler",
    "security_headers_manager": "guard_core.handlers.security_headers_handler",
    "SecurityHeadersManager": "guard_core.handlers.security_headers_handler",
    "sus_patterns_handler": "guard_core.handlers.suspatterns_handler",
    "GeoIPHandler": "guard_core.protocols.geo_ip_protocol",
    "RedisHandlerProtocol": "guard_core.protocols.redis_protocol",
    "BoundedBodyReader": "guard_core.protocols.request_protocol",
    "GuardRequest": "guard_core.protocols.request_protocol",
    "GuardResponse": "guard_core.protocols.response_protocol",
    "GuardResponseFactory": "guard_core.protocols.response_protocol",
    "BoundedResponseBodyReader": "guard_core.protocols.response_protocol",
    "is_ip_allowed": "guard_core.utils",
    "check_ip_access": "guard_core.utils",
    "check_rate_limit_by_ip": "guard_core.handlers.ratelimit_handler",
    "_mute_pydantic_plugin_instrumentation": "guard_core._pydantic_plugin_mute",
}


def __getattr__(name: str) -> Any:
    module_name = _MODULE_BY_NAME.get(name)
    if module_name is not None:
        value = getattr(import_module(module_name), name)
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
