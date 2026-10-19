import logging
from typing import Any

from guard_core._redis_enablement import redis_is_configured

logger = logging.getLogger("guard_core.models")

DEFAULT_REDIS_PREFIX = "guard_core:"

_default_prefix_warned = False


def _warn_default_redis_prefix() -> None:
    global _default_prefix_warned
    if _default_prefix_warned:
        return
    _default_prefix_warned = True
    logger.warning(
        "redis_prefix is the default %r while Redis is enabled: every app on the "
        "same Redis that keeps the default shares its bans and rate-limit counters. "
        "Set a unique redis_prefix per app. This warning is logged once.",
        DEFAULT_REDIS_PREFIX,
    )


def _warn_staged_defaults(config: Any) -> None:
    if redis_is_configured(config) and config.redis_prefix == DEFAULT_REDIS_PREFIX:
        _warn_default_redis_prefix()
