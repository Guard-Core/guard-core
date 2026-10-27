import logging
from typing import Protocol

from guard_core._redis_enablement import (
    RedisFieldsConfig,
    redis_connection_field_set_explicitly,
    redis_is_configured,
)
from guard_core._utils.sampling import PerApp, WarnedKeys

logger = logging.getLogger("guard_core.models")


class StagedDefaultsConfig(RedisFieldsConfig, Protocol):
    @property
    def enable_rate_limiting(self) -> bool: ...

    @property
    def whitelist(self) -> tuple[str, ...] | None: ...

    @property
    def exclude_paths(self) -> list[str]: ...

    @property
    def redis_prefix(self) -> str: ...


DEFAULT_REDIS_PREFIX = "guard_core:"

_default_prefix_warned = False

_BAN_ON_HOSTILE_SIGNALS_ENTRY = (
    "ban_on_hostile_signals is now True, so failed authentication, missing "
    "required headers, bad referrers, block-list hits and clear X-Forwarded-For "
    "forgery count toward automatic bans (restore: ban_on_hostile_signals=False)"
)
_FAIL_ON_MISCONFIGURATION_ENTRY = (
    "fail_on_misconfiguration is now True, so a misconfiguration refuses to "
    "start (restore: fail_on_misconfiguration=False)"
)
_RATE_LIMIT_ENTRY = "rate_limit is now 120 per 60 s, it was 10 (restore: rate_limit=10)"
_WHITELIST_ACCESS_ONLY_ENTRY = (
    "whitelist_access_only is now True, so a whitelisted IP is rate limited, "
    "user-agent and cloud checked, scanned for attacks and can be banned, and "
    "only exempt_ips skips those checks (restore: whitelist_access_only=False)"
)
_REDIS_OFF_ENTRY = (
    "enable_redis is now off unless a Redis connection field (redis_url, "
    "redis_prefix and the other redis_* settings) is set, it was always on "
    "(restore: enable_redis=True)"
)
_SLASH_EXCLUSION_ENTRY = (
    "exclude_paths entry '/' now covers only the root page, it covered the whole "
    "application (restore: exclude_all_paths=True)"
)


FLIP_IDS = (
    "ban_on_hostile_signals",
    "fail_on_misconfiguration",
    "rate_limit",
    "whitelist_access_only",
    "slash_exclusion",
    "enable_redis",
)

SIGNAL_TRIGGER_FIELDS = frozenset(
    {
        "exclude_paths",
        "exclude_all_paths",
        "whitelist",
        "whitelist_access_only",
        "rate_limit",
        "enable_rate_limiting",
        "enable_redis",
    }
)

_changed_defaults_logged = PerApp("changed_defaults", WarnedKeys)


def _redis_kept_on_entry(field: str) -> str:
    return (
        f"enable_redis stays on because {field} is set; it is now off when no "
        "Redis connection field is set, it was always on (to state it: "
        "enable_redis=True)"
    )


def _redis_entry(config: StagedDefaultsConfig) -> str | None:
    if "enable_redis" in config.model_fields_set:
        return None
    field = redis_connection_field_set_explicitly(config)
    return _REDIS_OFF_ENTRY if field is None else _redis_kept_on_entry(field)


def _changed_default_entries(config: StagedDefaultsConfig) -> list[tuple[str, str]]:
    stated = config.model_fields_set
    redis_entry = _redis_entry(config)
    candidates = (
        ("ban_on_hostile_signals" not in stated, _BAN_ON_HOSTILE_SIGNALS_ENTRY),
        ("fail_on_misconfiguration" not in stated, _FAIL_ON_MISCONFIGURATION_ENTRY),
        (config.enable_rate_limiting and "rate_limit" not in stated, _RATE_LIMIT_ENTRY),
        (
            bool(config.whitelist) and "whitelist_access_only" not in stated,
            _WHITELIST_ACCESS_ONLY_ENTRY,
        ),
        (
            "/" in config.exclude_paths and "exclude_all_paths" not in stated,
            _SLASH_EXCLUSION_ENTRY,
        ),
        (redis_entry is not None, redis_entry),
    )
    return [
        (flip_id, entry)
        for flip_id, (applies, entry) in zip(FLIP_IDS, candidates, strict=True)
        if applies and entry is not None
    ]


def signal_changed_defaults(config: StagedDefaultsConfig) -> None:
    logged = _changed_defaults_logged.for_app(config)
    fresh = [
        (flip_id, entry)
        for flip_id, entry in _changed_default_entries(config)
        if flip_id not in logged
    ]
    if not fresh:
        return
    logged.update(flip_id for flip_id, _ in fresh)
    logger.warning(
        "guard-core 5.0.0 changed defaults that this configuration leaves unset: "
        "%s. Each default is logged once per configuration.",
        "; ".join(entry for _, entry in fresh),
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


def warn_redis_prefix_left_default(config: StagedDefaultsConfig) -> None:
    if redis_is_configured(config) and config.redis_prefix == DEFAULT_REDIS_PREFIX:
        _warn_default_redis_prefix()
