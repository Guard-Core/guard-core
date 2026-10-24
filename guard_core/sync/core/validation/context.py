from dataclasses import dataclass
from logging import Logger

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.events import SecurityEventBus


@dataclass
class ValidationContext:
    config: SyncSecurityConfig
    logger: Logger
    event_bus: SecurityEventBus
