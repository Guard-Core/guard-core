import inspect
from typing import Any

DYNAMIC_RULES_REDIS_NAMESPACE = "dynamic_rules"
LAST_KNOWN_RULES_KEY = "last_known"
OWNED_BANS_KEY = "owned_bans"
BAN_FLOORS_NAMESPACE = "ban_floors"


def resolve_redis_value(value: Any) -> Any:
    if inspect.isawaitable(value):
        closer = getattr(value, "close", None)
        if closer is not None:
            closer()
        raise TypeError(
            "async redis handler not supported in sync (WSGI) deployments; "
            "supply a sync redis handler"
        )
    return value
