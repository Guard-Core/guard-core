from typing_extensions import assert_type

from guard_core.models import SecurityConfig
from guard_core.sync.decorators import SecurityDecorator, get_route_id

guard = SecurityDecorator(SecurityConfig(ipinfo_token="token"))


@guard.require_https()
@guard.rate_limit(5, 60)
@guard.block_countries(["XX"])
def sync_route(name: str, *, times: int = 1) -> str:
    return name * times


@guard.require_auth("bearer")
def second_route(count: int) -> list[int]:
    return [count]


class Handler:
    @guard.require_ip(whitelist=["10.0.0.1"])
    def get(self, item_id: int) -> dict[str, int]:
        return {"id": item_id}


assert_type(sync_route("a", times=2), str)
assert_type(Handler().get(1), dict[str, int])
assert_type(get_route_id(sync_route), str)
assert_type(second_route(1), list[int])
