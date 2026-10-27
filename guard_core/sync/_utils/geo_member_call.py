from typing import TYPE_CHECKING, Literal, TypeAlias

if TYPE_CHECKING:
    from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler

GeoMemberName: TypeAlias = Literal[
    "initialize", "initialize_redis", "initialize_agent", "ensure_database_loaded"
]


def settle_geo_member_call(
    handler: "SyncGeoIPHandler", member: GeoMemberName, *arguments: object
) -> None:
    getattr(handler, member)(*arguments)
