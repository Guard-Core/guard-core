from dataclasses import dataclass
from logging import Logger

from guard_core.sync.decorators.base import BaseSecurityDecorator
from guard_core.models import SecurityConfig, SyncSecurityConfig


@dataclass
class RoutingContext:
    config: SyncSecurityConfig
    logger: Logger

    guard_decorator: BaseSecurityDecorator | None = None
