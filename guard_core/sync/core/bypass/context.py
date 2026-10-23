from dataclasses import dataclass
from logging import Logger

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.events import SecurityEventBus
from guard_core.sync.core.responses import ErrorResponseFactory
from guard_core.sync.core.routing import RouteConfigResolver
from guard_core.sync.core.validation import RequestValidator


@dataclass
class BypassContext:
    config: SyncSecurityConfig
    logger: Logger
    event_bus: SecurityEventBus
    route_resolver: RouteConfigResolver
    response_factory: ErrorResponseFactory
    validator: RequestValidator
