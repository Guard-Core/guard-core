from dataclasses import dataclass
from logging import Logger
from typing import TYPE_CHECKING

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.events import SecurityEventBus
from guard_core.sync.decorators.base import BaseSecurityDecorator

if TYPE_CHECKING:
    from guard_core.sync.handlers.behavior_handler import BehaviorTracker


@dataclass
class BehavioralContext:
    config: SyncSecurityConfig
    logger: Logger
    event_bus: SecurityEventBus
    guard_decorator: BaseSecurityDecorator | None
    behavior_tracker: "BehaviorTracker | None" = None
    middleware: object | None = None
