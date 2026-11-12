import logging
from typing import Protocol

from guard_core._misconfiguration_kinds import (
    K_CHANGED_DEFAULT_BAN_ON_HOSTILE_SIGNALS,
    K_CHANGED_DEFAULT_ENABLE_REDIS,
    K_CHANGED_DEFAULT_FAIL_ON_MISCONFIGURATION,
    K_CHANGED_DEFAULT_RATE_LIMIT,
    K_CHANGED_DEFAULT_SLASH_EXCLUSION,
    K_CHANGED_DEFAULT_WHITELIST_ACCESS_ONLY,
    K_REDIS_PREFIX_LEFT_DEFAULT,
    kinds_log_extra,
)
from guard_core._redis_enablement import (
    REDIS_CONNECTION_FIELDS,
    RedisFieldsConfig,
    redis_connection_field_set_explicitly,
)
from guard_core._redis_enablement import (
    redis_is_configured as redis_is_configured,
)
from guard_core._utils.sampling import PerApp, WarnedKeys

logger = logging.getLogger("guard_core.models")


class StagedDefaultsConfig(RedisFieldsConfig, Protocol):
    __pydantic_fields_set__: set[str]

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

_CHANGED_DEFAULT_KINDS = {
    "ban_on_hostile_signals": K_CHANGED_DEFAULT_BAN_ON_HOSTILE_SIGNALS,
    "fail_on_misconfiguration": K_CHANGED_DEFAULT_FAIL_ON_MISCONFIGURATION,
    "rate_limit": K_CHANGED_DEFAULT_RATE_LIMIT,
    "whitelist_access_only": K_CHANGED_DEFAULT_WHITELIST_ACCESS_ONLY,
    "slash_exclusion": K_CHANGED_DEFAULT_SLASH_EXCLUSION,
    "enable_redis": K_CHANGED_DEFAULT_ENABLE_REDIS,
}


def _redis_kept_on_entry(field: str) -> str:
    return (
        f"enable_redis stays on because {field} is set; it is now off when no "
        "Redis connection field is set, it was always on (to state it: "
        "enable_redis=True)"
    )


def _redis_entry(config: StagedDefaultsConfig, stated: set[str]) -> str | None:
    if "enable_redis" in stated:
        return None
    field = redis_connection_field_set_explicitly(config)
    return _REDIS_OFF_ENTRY if field is None else _redis_kept_on_entry(field)


def _changed_default_entries(config: StagedDefaultsConfig) -> list[tuple[str, str]]:
    stated = config.__pydantic_fields_set__
    entries: list[tuple[str, str]] = []
    if "ban_on_hostile_signals" not in stated:
        entries.append(("ban_on_hostile_signals", _BAN_ON_HOSTILE_SIGNALS_ENTRY))
    if "fail_on_misconfiguration" not in stated:
        entries.append(("fail_on_misconfiguration", _FAIL_ON_MISCONFIGURATION_ENTRY))
    if config.enable_rate_limiting and "rate_limit" not in stated:
        entries.append(("rate_limit", _RATE_LIMIT_ENTRY))
    if config.whitelist and "whitelist_access_only" not in stated:
        entries.append(("whitelist_access_only", _WHITELIST_ACCESS_ONLY_ENTRY))
    if "/" in config.exclude_paths and "exclude_all_paths" not in stated:
        entries.append(("slash_exclusion", _SLASH_EXCLUSION_ENTRY))
    redis_entry = _redis_entry(config, stated)
    if redis_entry is not None:
        entries.append(("enable_redis", redis_entry))
    return entries


# The entries of a configuration that states none of these fields and keeps rate
# limiting on, no whitelist and no "/" in exclude_paths: the four flips below, in
# the order _changed_default_entries lists them. Built once so the first
# SecurityConfig() of a process does not rebuild what every default config says.
_UNSTATED_ENTRY_FIELDS = frozenset(
    {
        "ban_on_hostile_signals",
        "fail_on_misconfiguration",
        "rate_limit",
        "enable_redis",
        *REDIS_CONNECTION_FIELDS,
    }
)
_DEFAULT_ENTRIES = (
    ("ban_on_hostile_signals", _BAN_ON_HOSTILE_SIGNALS_ENTRY),
    ("fail_on_misconfiguration", _FAIL_ON_MISCONFIGURATION_ENTRY),
    ("rate_limit", _RATE_LIMIT_ENTRY),
    ("enable_redis", _REDIS_OFF_ENTRY),
)
# A configuration that states all of these lists nothing for them, and lists
# nothing for the whitelist or the "/" entry when it has neither.
_ALWAYS_LISTED_FIELDS = frozenset(
    {"ban_on_hostile_signals", "fail_on_misconfiguration", "rate_limit", "enable_redis"}
)
_DEFAULT_ENTRY_IDS = tuple(flip_id for flip_id, _ in _DEFAULT_ENTRIES)
_DEFAULT_ENTRY_TEXT = "; ".join(entry for _, entry in _DEFAULT_ENTRIES)


def _states_only_defaults(config: StagedDefaultsConfig) -> bool:
    return (
        config.__pydantic_fields_set__.isdisjoint(_UNSTATED_ENTRY_FIELDS)
        and config.enable_rate_limiting
        and not config.whitelist
        and "/" not in config.exclude_paths
    )


def _states_every_changed_default(config: StagedDefaultsConfig) -> bool:
    return (
        config.__pydantic_fields_set__ >= _ALWAYS_LISTED_FIELDS
        and not config.whitelist
        and "/" not in config.exclude_paths
    )


def signal_changed_defaults(config: StagedDefaultsConfig) -> None:
    if _states_every_changed_default(config):
        return
    entries = (
        _DEFAULT_ENTRIES
        if _states_only_defaults(config)
        else _changed_default_entries(config)
    )
    if not entries:
        return
    logged = _changed_defaults_logged.for_app(config)
    if logged:
        entries = [pair for pair in entries if pair[0] not in logged]
        if not entries:
            return
    if entries is _DEFAULT_ENTRIES:
        logged.update(_DEFAULT_ENTRY_IDS)
        text = _DEFAULT_ENTRY_TEXT
        flips = _DEFAULT_ENTRY_IDS
    else:
        texts = dict(entries)
        logged.update(texts)
        text = "; ".join(texts.values())
        flips = tuple(texts)
    logger.warning(
        "guard-core 5.0.0 changed defaults that this configuration leaves unset: "
        "%s. Each default is logged once per configuration.",
        text,
        extra={
            "problems": tuple((_CHANGED_DEFAULT_KINDS[flip], None) for flip in flips)
        },
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
        extra=kinds_log_extra(K_REDIS_PREFIX_LEFT_DEFAULT, None),
    )


def warn_redis_prefix_left_default(config: StagedDefaultsConfig) -> None:
    if (
        config.enable_redis
        and config.redis_url
        and config.redis_prefix == DEFAULT_REDIS_PREFIX
    ):
        _warn_default_redis_prefix()
