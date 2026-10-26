from dataclasses import dataclass
from logging import Logger
from typing import TYPE_CHECKING

from guard_core.core.events import SecurityEventBus
from guard_core.decorators.base import BaseSecurityDecorator
from guard_core.models import SecurityConfig

if TYPE_CHECKING:
    from guard_core.handlers.behavior_handler import BehaviorTracker


@dataclass
class BehavioralContext:
    config: SecurityConfig
    logger: Logger
    event_bus: SecurityEventBus
    guard_decorator: BaseSecurityDecorator | None
    behavior_tracker: "BehaviorTracker | None" = None
    middleware: object | None = None
