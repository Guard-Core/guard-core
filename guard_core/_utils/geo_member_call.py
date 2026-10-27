import inspect
from typing import TYPE_CHECKING, Literal, TypeAlias

if TYPE_CHECKING:
    from guard_core._geo_handler_for_tree import GeoIPHandlerOfThisTree

GeoMemberName: TypeAlias = Literal[
    "initialize", "initialize_redis", "initialize_agent", "ensure_database_loaded"
]


async def settle_geo_member_call(
    handler: "GeoIPHandlerOfThisTree", member: GeoMemberName, *arguments: object
) -> None:
    result = getattr(handler, member)(*arguments)
    if inspect.isawaitable(result):
        await result
