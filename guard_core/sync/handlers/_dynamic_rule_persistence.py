import inspect
from collections.abc import Awaitable
from typing import NoReturn, TypeVar, overload

DYNAMIC_RULES_REDIS_NAMESPACE = "dynamic_rules"
LAST_KNOWN_RULES_KEY = "last_known"
LAST_KNOWN_RULES_FULL_KEY = "last_known_full"
LAST_KNOWN_RULES_FULL_FILE_SUFFIX = ".full"
OWNED_BANS_KEY = "owned_bans"
PURGED_MARKER_KEY = "purged"
BAN_FLOORS_NAMESPACE = "ban_floors"


_Value = TypeVar("_Value")


@overload
def resolve_redis_value(value: Awaitable[object]) -> NoReturn: ...


@overload
def resolve_redis_value(value: _Value) -> _Value: ...


def resolve_redis_value(value: object) -> object:
    if inspect.isawaitable(value):
        closer = getattr(value, "close", None)
        if closer is not None:
            closer()
        raise TypeError(
            "async redis handler not supported in sync (WSGI) deployments; "
            "supply a sync redis handler"
        )
    return value


def parse_purge_target(value: str) -> tuple[str, int]:
    """Split "rule_id:version" at its last colon, so an id may hold colons."""
    rule_id, separator, version = value.rpartition(":")
    if not separator or not rule_id or not version.isdecimal():
        raise ValueError(
            f"purge_dynamic_rules_on_start must be 'rule_id:version', got {value!r}"
        )
    return rule_id, int(version)
