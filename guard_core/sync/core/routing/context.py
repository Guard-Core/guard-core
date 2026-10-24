from dataclasses import dataclass
from logging import Logger

from guard_core.models import SyncSecurityConfig
from guard_core.sync.decorators.base import BaseSecurityDecorator


@dataclass
class RoutingContext:
    config: SyncSecurityConfig
    logger: Logger

    guard_decorator: BaseSecurityDecorator | None = None
