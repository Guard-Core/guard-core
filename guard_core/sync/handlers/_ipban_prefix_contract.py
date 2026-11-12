import logging
from typing import TYPE_CHECKING

from guard_core._misconfiguration import report_misconfiguration
from guard_core._misconfiguration_kinds import (
    K_IPV6_PREFIX_LENGTH_REDIS_MISMATCH,
    Problem,
)

if TYPE_CHECKING:
    from guard_core.models import SyncSecurityConfig
    from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol

_NAMESPACE = "config"
_KEY = "ipv6_prefix_length"


def _recorded_prefix_length(
    redis_handler: "SyncRedisHandlerProtocol", wanted: int, logger: logging.Logger
) -> tuple[str | None, str]:
    key = f"{redis_handler.config.redis_prefix}{_NAMESPACE}:{_KEY}"
    try:
        if redis_handler.set_key_if_absent(_NAMESPACE, _KEY, str(wanted)):
            return None, key
        recorded = redis_handler.get_key(_NAMESPACE, _KEY)
    except Exception as error:
        logger.warning(
            "The recorded ipv6_prefix_length could not be checked: %s", error
        )
        return None, key
    return (None if recorded is None else str(recorded)), key


def enforce_prefix_length_contract(
    redis_handler: "SyncRedisHandlerProtocol",
    config: "SyncSecurityConfig",
    logger: logging.Logger,
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
    recorded, key = _recorded_prefix_length(redis_handler, wanted, logger)
    if recorded is None or recorded == str(wanted):
        return
    report_misconfiguration(
        config,
        Problem(
            f"ipv6_prefix_length is {wanted} here but {recorded} on the workers "
            f"that share this Redis (recorded in the key {key}); bans and "
            "rate-limit windows would use different identities. A rolling change "
            "is not supported: stop all workers, delete that key or use a new "
            "redis_prefix, then start them with one value.",
            kind=K_IPV6_PREFIX_LENGTH_REDIS_MISMATCH,
        ),
        logger=logger,
        stacklevel=4,
    )
