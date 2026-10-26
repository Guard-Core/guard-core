import logging
from typing import TYPE_CHECKING

from typing_extensions import get_protocol_members

from guard_core._misconfiguration import report_misconfiguration
from guard_core.protocols.redis_protocol import RedisHandlerProtocol

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig


def missing_redis_handler_members(handler: object) -> list[str]:
    return sorted(
        name
        for name in get_protocol_members(RedisHandlerProtocol)
        if not hasattr(handler, name)
    )


def report_incomplete_redis_handler(
    config: "SecurityConfig", handler: object, logger: logging.Logger
) -> None:
    missing = missing_redis_handler_members(handler)
    if missing:
        report_misconfiguration(
            config,
            f"The Redis handler {type(handler).__name__} lacks "
            f"{', '.join(missing)}, which the engine calls; subclass "
            "RedisHandlerBase for the defaults.",
            logger=logger,
            stacklevel=5,
        )
