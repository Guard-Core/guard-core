import importlib.util
from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .behavior_handler import BehaviorTracker
    from .cloud_handler import CloudManager
    from .cors_handler import CorsHandler, CorsPreflightResponse, is_preflight
    from .dynamic_rule_handler import DynamicRuleManager
    from .ipban_handler import IPBanManager
    from .ipinfo_handler import IPInfoManager
    from .ratelimit_handler import RateLimitManager
    from .redis_handler import RedisHandlerBase, RedisManager
    from .security_headers_handler import SecurityHeadersManager
    from .suspatterns_handler import SusPatternsManager

__all__ = [
    "BehaviorTracker",
    "CloudManager",
    "CorsHandler",
    "CorsPreflightResponse",
    "DynamicRuleManager",
    "IPBanManager",
    "IPInfoManager",
    "RateLimitManager",
    "RedisHandlerBase",
    "RedisManager",
    "SecurityHeadersManager",
    "SusPatternsManager",
    "is_preflight",
]

_MODULE_BY_NAME: dict[str, str] = {
    "BehaviorTracker": "guard_core.sync.handlers.behavior_handler",
    "CloudManager": "guard_core.sync.handlers.cloud_handler",
    "CorsHandler": "guard_core.sync.handlers.cors_handler",
    "CorsPreflightResponse": "guard_core.sync.handlers.cors_handler",
    "is_preflight": "guard_core.sync.handlers.cors_handler",
    "DynamicRuleManager": "guard_core.sync.handlers.dynamic_rule_handler",
    "IPBanManager": "guard_core.sync.handlers.ipban_handler",
    "IPInfoManager": "guard_core.sync.handlers.ipinfo_handler",
    "RateLimitManager": "guard_core.sync.handlers.ratelimit_handler",
    "RedisHandlerBase": "guard_core.sync.handlers.redis_handler",
    "RedisManager": "guard_core.sync.handlers.redis_handler",
    "SecurityHeadersManager": "guard_core.sync.handlers.security_headers_handler",
    "SusPatternsManager": "guard_core.sync.handlers.suspatterns_handler",
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
