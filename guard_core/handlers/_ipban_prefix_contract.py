import logging
from typing import Any

from guard_core._misconfiguration import report_misconfiguration

_NAMESPACE = "config"
_KEY = "ipv6_prefix_length"


async def _recorded_prefix_length(
    redis_handler: Any, wanted: int, logger: logging.Logger
) -> tuple[str | None, str]:
    key = f"{redis_handler.config.redis_prefix}{_NAMESPACE}:{_KEY}"
    try:
        if await redis_handler.set_key_if_absent(_NAMESPACE, _KEY, str(wanted)):
            return None, key
        recorded = await redis_handler.get_key(_NAMESPACE, _KEY)
    except Exception as error:
        logger.warning(
            "The recorded ipv6_prefix_length could not be checked: %s", error
        )
        return None, key
    return (None if recorded is None else str(recorded)), key


async def enforce_prefix_length_contract(
    redis_handler: Any, config: Any, logger: logging.Logger
) -> None:
    """Make every worker on one Redis agree on ipv6_prefix_length.

    The first worker records its value with SET NX. A worker whose value differs
    would key bans and rate-limit windows differently from the others, so it is
    reported through fail_on_misconfiguration (fatal by default, a warning when it
    is False) and the recorded value is left alone.
    """
    wanted = getattr(config, "ipv6_prefix_length", None)
    if wanted is None:
        return
    recorded, key = await _recorded_prefix_length(redis_handler, wanted, logger)
    if recorded is None or recorded == str(wanted):
        return
    report_misconfiguration(
        config,
        f"ipv6_prefix_length is {wanted} here but {recorded} on the workers "
        f"that share this Redis (recorded in the key {key}); bans and "
        "rate-limit windows would use different identities. A rolling change "
        "is not supported: stop all workers, delete that key or use a new "
        "redis_prefix, then start them with one value.",
        logger=logger,
        stacklevel=4,
    )
