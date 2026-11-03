from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guard_core.protocols.agent_protocol import AgentHandlerProtocol
    from guard_core.protocols.geo_ip_protocol import GeoIPHandler
    from guard_core.protocols.middleware_protocol import GuardMiddlewareProtocol
    from guard_core.protocols.redis_protocol import RedisHandlerProtocol
    from guard_core.protocols.request_protocol import (
        BoundedBodyReader,
        GuardRequest,
        GuardRequestHeaders,
        IdleBoundedBodyReader,
    )
    from guard_core.protocols.response_protocol import (
        BoundedResponseBodyReader,
        GuardResponse,
        GuardResponseFactory,
        GuardResponseHeaders,
        MaterializedBodyResponse,
    )
    from guard_core.protocols.route_identity import RouteIdentity

__all__ = [
    "RouteIdentity",
    "AgentHandlerProtocol",
    "BoundedBodyReader",
    "BoundedResponseBodyReader",
    "GeoIPHandler",
    "GuardMiddlewareProtocol",
    "GuardRequest",
    "GuardRequestHeaders",
    "GuardResponse",
    "GuardResponseFactory",
    "GuardResponseHeaders",
    "IdleBoundedBodyReader",
    "MaterializedBodyResponse",
    "RedisHandlerProtocol",
]

_MODULE_BY_NAME: dict[str, str] = {
    "AgentHandlerProtocol": "guard_core.protocols.agent_protocol",
    "GeoIPHandler": "guard_core.protocols.geo_ip_protocol",
    "GuardMiddlewareProtocol": "guard_core.protocols.middleware_protocol",
    "RedisHandlerProtocol": "guard_core.protocols.redis_protocol",
    "BoundedBodyReader": "guard_core.protocols.request_protocol",
    "GuardRequest": "guard_core.protocols.request_protocol",
    "GuardRequestHeaders": "guard_core.protocols.request_protocol",
    "IdleBoundedBodyReader": "guard_core.protocols.request_protocol",
    "BoundedResponseBodyReader": "guard_core.protocols.response_protocol",
    "GuardResponse": "guard_core.protocols.response_protocol",
    "GuardResponseFactory": "guard_core.protocols.response_protocol",
    "GuardResponseHeaders": "guard_core.protocols.response_protocol",
    "MaterializedBodyResponse": "guard_core.protocols.response_protocol",
    "RouteIdentity": "guard_core.protocols.route_identity",
}


def __getattr__(name: str) -> object:
    module_name = _MODULE_BY_NAME.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
