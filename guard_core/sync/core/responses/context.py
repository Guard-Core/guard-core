from dataclasses import dataclass, field
from logging import Logger
from typing import Any

from guard_core.models import SecurityConfig
from guard_core.sync.core.events import MetricsCollector
from guard_core.sync.decorators.base import BaseSecurityDecorator
from guard_core.sync.handlers.security_headers_handler import SecurityHeadersManager


@dataclass
class ResponseContext:
    config: SecurityConfig
    logger: Logger
    metrics_collector: MetricsCollector

    agent_handler: Any | None = None
    guard_decorator: BaseSecurityDecorator | None = None
    response_factory: Any = field(default=None)
    security_headers_manager: SecurityHeadersManager = field(
        default_factory=SecurityHeadersManager.isolated
    )
