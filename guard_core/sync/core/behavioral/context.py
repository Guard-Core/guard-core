from dataclasses import dataclass
from logging import Logger
from typing import Any

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.events import SecurityEventBus
from guard_core.sync.decorators.base import BaseSecurityDecorator


@dataclass
class BehavioralContext:
    config: SyncSecurityConfig
    logger: Logger
    event_bus: SecurityEventBus
    guard_decorator: BaseSecurityDecorator | None
    behavior_tracker: Any | None = None
    middleware: Any = None
