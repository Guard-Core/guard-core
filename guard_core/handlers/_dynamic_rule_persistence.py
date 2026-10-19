import inspect
from typing import Any

DYNAMIC_RULES_REDIS_NAMESPACE = "dynamic_rules"
LAST_KNOWN_RULES_KEY = "last_known"
OWNED_BANS_KEY = "owned_bans"
BAN_FLOORS_NAMESPACE = "ban_floors"


async def resolve_redis_value(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value
