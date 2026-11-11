import importlib.util
from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig
    from guard_core.sync._utils.app_managers import release_app
    from guard_core.sync.decorators import RouteConfig, SecurityDecorator
    from guard_core.sync.handlers._dynamic_rule_validation import (
        endpoint_rate_limit_key_problems,
    )
    from guard_core.sync.handlers._security_headers_apply import (
        apply_security_headers_settings,
    )
    from guard_core.sync.handlers.behavior_handler import BehaviorRule, BehaviorTracker
    from guard_core.sync.handlers.cloud_handler import CloudManager, cloud_handler
    from guard_core.sync.handlers.ipban_handler import IPBanManager, ip_ban_manager
    from guard_core.sync.handlers.ipinfo_handler import IPInfoManager
    from guard_core.sync.handlers.ratelimit_handler import (
        RateLimitManager,
        check_rate_limit_by_ip,
        rate_limit_handler,
    )
    from guard_core.sync.handlers.redis_handler import (
        RedisHandlerBase,
        RedisManager,
        redis_handler,
    )
    from guard_core.sync.handlers.security_headers_handler import (
        SecurityHeadersManager,
        security_headers_manager,
    )
    from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
    from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler
    from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol
    from guard_core.sync.protocols.request_protocol import (
        SyncBoundedBodyReader,
        SyncGuardRequest,
    )
    from guard_core.sync.protocols.response_protocol import (
        GuardResponse,
        GuardResponseFactory,
        SyncBoundedResponseBodyReader,
    )

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
    "check_rate_limit_by_ip",
    "redis_handler",
    "RedisHandlerBase",
    "RedisManager",
    "security_headers_manager",
    "apply_security_headers_settings",
    "endpoint_rate_limit_key_problems",
    "SecurityHeadersManager",
    "sus_patterns_handler",
    "SyncBoundedBodyReader",
    "SyncBoundedResponseBodyReader",
    "SyncGeoIPHandler",
    "SyncRedisHandlerProtocol",
    "SyncGuardRequest",
    "GuardResponse",
    "GuardResponseFactory",
    "release_app",
]

_MODULE_BY_NAME: dict[str, str] = {
    "SecurityConfig": "guard_core.models",
    "SecurityDecorator": "guard_core.sync.decorators",
    "RouteConfig": "guard_core.sync.decorators",
    "BehaviorTracker": "guard_core.sync.handlers.behavior_handler",
    "BehaviorRule": "guard_core.sync.handlers.behavior_handler",
    "ip_ban_manager": "guard_core.sync.handlers.ipban_handler",
    "IPBanManager": "guard_core.sync.handlers.ipban_handler",
    "cloud_handler": "guard_core.sync.handlers.cloud_handler",
    "CloudManager": "guard_core.sync.handlers.cloud_handler",
    "IPInfoManager": "guard_core.sync.handlers.ipinfo_handler",
    "rate_limit_handler": "guard_core.sync.handlers.ratelimit_handler",
    "RateLimitManager": "guard_core.sync.handlers.ratelimit_handler",
    "check_rate_limit_by_ip": "guard_core.sync.handlers.ratelimit_handler",
    "redis_handler": "guard_core.sync.handlers.redis_handler",
    "RedisHandlerBase": "guard_core.sync.handlers.redis_handler",
    "RedisManager": "guard_core.sync.handlers.redis_handler",
    "security_headers_manager": "guard_core.sync.handlers.security_headers_handler",
    "apply_security_headers_settings": (
        "guard_core.sync.handlers._security_headers_apply"
    ),
    "endpoint_rate_limit_key_problems": (
        "guard_core.sync.handlers._dynamic_rule_validation"
    ),
    "SecurityHeadersManager": "guard_core.sync.handlers.security_headers_handler",
    "sus_patterns_handler": "guard_core.sync.handlers.suspatterns_handler",
    "SyncGeoIPHandler": "guard_core.sync.protocols.geo_ip_protocol",
    "SyncRedisHandlerProtocol": "guard_core.sync.protocols.redis_protocol",
    "SyncBoundedBodyReader": "guard_core.sync.protocols.request_protocol",
    "SyncGuardRequest": "guard_core.sync.protocols.request_protocol",
    "GuardResponse": "guard_core.sync.protocols.response_protocol",
    "GuardResponseFactory": "guard_core.sync.protocols.response_protocol",
    "SyncBoundedResponseBodyReader": "guard_core.sync.protocols.response_protocol",
    "release_app": "guard_core.sync._utils.app_managers",
}


def __getattr__(name: str) -> object:
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
