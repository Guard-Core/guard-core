import logging
import warnings
from typing import Any

logger = logging.getLogger("guard_core.models")

DEFAULT_REDIS_PREFIX = "guard_core:"

_redis_default_warned = False
_rate_limit_default_warned = False
_default_prefix_warned = False
_whitelist_access_only_warned = False

_REDIS_DEFAULT_WARNING = (
    "enable_redis is not set. guard-core 5.0.0 turns it off by default, so an app "
    "that never configured Redis stops connecting to a Redis on localhost. Pass "
    "enable_redis=True to SecurityConfig now to keep using Redis, or "
    "enable_redis=False to opt in to the 5.0.0 default. This warning is logged once."
)

_RATE_LIMIT_DEFAULT_WARNING = (
    "rate_limit is not set, so the default of 10 requests per rate_limit_window "
    "(60 s) applies. guard-core 5.0.0 raises the default to 120 requests per 60 s. "
    "Pass rate_limit=10 to SecurityConfig to keep today's limit, or rate_limit=120 "
    "to opt in now. This warning is logged once."
)


_WHITELIST_ACCESS_ONLY_WARNING = (
    "whitelist_access_only is not set. guard-core 5.0.0 turns it on: the global "
    "whitelist then only admits an IP and no longer skips rate limiting, the "
    "user-agent check, the cloud-provider check or attack detection, so a "
    "whitelisted IP collects hostile-signal strikes and identity escalation like "
    "any other client, a whitelisted address or CIDR can be banned and the ban is "
    "enforced, and all of it reaches every admitted request. Move the hosts that "
    "need those skips to exempt_ips. Pass whitelist_access_only=True to "
    "SecurityConfig now to opt in, or whitelist_access_only=False to keep today's "
    "behavior. This warning is logged once."
)


def _warn_redis_default_on(*, stacklevel: int) -> None:
    global _redis_default_warned
    if _redis_default_warned:
        return
    _redis_default_warned = True
    logger.warning(_REDIS_DEFAULT_WARNING)
    warnings.warn(_REDIS_DEFAULT_WARNING, DeprecationWarning, stacklevel=stacklevel)


def _warn_rate_limit_default_in_effect(*, stacklevel: int) -> None:
    global _rate_limit_default_warned
    if _rate_limit_default_warned:
        return
    _rate_limit_default_warned = True
    logger.warning(_RATE_LIMIT_DEFAULT_WARNING)
    warnings.warn(
        _RATE_LIMIT_DEFAULT_WARNING, DeprecationWarning, stacklevel=stacklevel
    )


def _warn_whitelist_access_only_default_off(*, stacklevel: int) -> None:
    global _whitelist_access_only_warned
    if _whitelist_access_only_warned:
        return
    _whitelist_access_only_warned = True
    logger.warning(_WHITELIST_ACCESS_ONLY_WARNING)
    warnings.warn(
        _WHITELIST_ACCESS_ONLY_WARNING, DeprecationWarning, stacklevel=stacklevel
    )


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


def _warn_staged_defaults(config: Any, *, stacklevel: int) -> None:
    if "enable_redis" not in config.model_fields_set:
        _warn_redis_default_on(stacklevel=stacklevel + 1)
    if config.enable_rate_limiting and "rate_limit" not in config.model_fields_set:
        _warn_rate_limit_default_in_effect(stacklevel=stacklevel + 1)
    if config.whitelist and "whitelist_access_only" not in config.model_fields_set:
        _warn_whitelist_access_only_default_off(stacklevel=stacklevel + 1)
    if config.enable_redis and config.redis_prefix == DEFAULT_REDIS_PREFIX:
        _warn_default_redis_prefix()
