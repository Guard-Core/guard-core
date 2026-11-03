from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guard_core.sync.protocols.agent_protocol import SyncAgentHandlerProtocol
    from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler
    from guard_core.sync.protocols.middleware_protocol import (
        SyncGuardMiddlewareProtocol,
    )
    from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol
    from guard_core.sync.protocols.request_protocol import (
        SyncBoundedBodyReader,
        SyncGuardRequest,
        SyncIdleBoundedBodyReader,
    )
    from guard_core.sync.protocols.response_protocol import (
        GuardResponse,
        GuardResponseFactory,
        MaterializedBodyResponse,
        SyncBoundedResponseBodyReader,
    )
    from guard_core.sync.protocols.route_identity import RouteIdentity

__all__ = [
    "RouteIdentity",
    "MaterializedBodyResponse",
    "SyncAgentHandlerProtocol",
    "SyncBoundedBodyReader",
    "SyncBoundedResponseBodyReader",
    "SyncGeoIPHandler",
    "SyncGuardMiddlewareProtocol",
    "SyncGuardRequest",
    "SyncIdleBoundedBodyReader",
    "GuardResponse",
    "GuardResponseFactory",
    "SyncRedisHandlerProtocol",
]

_MODULE_BY_NAME: dict[str, str] = {
    "SyncAgentHandlerProtocol": "guard_core.sync.protocols.agent_protocol",
    "SyncGeoIPHandler": "guard_core.sync.protocols.geo_ip_protocol",
    "SyncGuardMiddlewareProtocol": "guard_core.sync.protocols.middleware_protocol",
    "SyncRedisHandlerProtocol": "guard_core.sync.protocols.redis_protocol",
    "SyncBoundedBodyReader": "guard_core.sync.protocols.request_protocol",
    "SyncGuardRequest": "guard_core.sync.protocols.request_protocol",
    "SyncIdleBoundedBodyReader": "guard_core.sync.protocols.request_protocol",
    "GuardResponse": "guard_core.sync.protocols.response_protocol",
    "GuardResponseFactory": "guard_core.sync.protocols.response_protocol",
    "MaterializedBodyResponse": "guard_core.sync.protocols.response_protocol",
    "SyncBoundedResponseBodyReader": "guard_core.sync.protocols.response_protocol",
    "RouteIdentity": "guard_core.sync.protocols.route_identity",
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
