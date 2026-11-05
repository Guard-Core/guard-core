import logging
from typing import TYPE_CHECKING

from typing_extensions import get_protocol_members

from guard_core._misconfiguration import report_misconfiguration
from guard_core.protocols.redis_protocol import RedisHandlerProtocol

if TYPE_CHECKING:
    from guard_core.models import SecurityConfig


def missing_redis_handler_members(
    handler: object, *, recovery_armable: bool = True
) -> list[str]:
    return sorted(
        name
        for name in get_protocol_members(RedisHandlerProtocol)
        if not hasattr(handler, name)
        and not (
            name == "is_connected"
            and (not recovery_armable or hasattr(handler, "_redis"))
        )
    )


def report_incomplete_redis_handler(
    config: "SecurityConfig", handler: object, logger: logging.Logger
) -> None:
    # Recovery is the only caller of is_connected, so this fail-open condition must
    # widen if anything else starts calling it.
    missing = missing_redis_handler_members(
        handler, recovery_armable=config.redis_fail_open
    )
    if missing:
        report_misconfiguration(
            config,
            f"The Redis handler {type(handler).__name__} lacks "
            f"{', '.join(missing)}, which the engine calls; subclass "
            "RedisHandlerBase for the defaults.",
            logger=logger,
            stacklevel=5,
        )
