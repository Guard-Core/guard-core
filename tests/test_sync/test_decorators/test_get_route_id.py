import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.decorators import SecurityDecorator, get_route_id


def test_route_id_is_still_set_at_runtime_and_readable_through_the_helper() -> None:
    guard = SecurityDecorator(SyncSecurityConfig())

    @guard.rate_limit(5, 60)
    def route() -> None:
        return None

    assert get_route_id(route) == route.__dict__["_guard_route_id"]


def test_route_id_of_an_undecorated_function_raises_attribute_error() -> None:
    def route() -> None:
        return None

    with pytest.raises(AttributeError, match="not decorated"):
        get_route_id(route)
