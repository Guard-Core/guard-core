from collections.abc import Callable
from typing import Any

import pytest

from guard_core.decorators import SecurityDecorator, get_route_id
from guard_core.models import SecurityConfig


def _decorator() -> SecurityDecorator:
    return SecurityDecorator(SecurityConfig(enable_redis=False))


def test_require_auth_after_presence_only_raises_and_changes_nothing() -> None:
    decorator = _decorator()

    def route() -> None:
        pass

    decorated = decorator.require_authorization_header("bearer")(route)
    route_config = decorator.get_route_config(get_route_id(decorated))
    assert route_config is not None

    with pytest.raises(ValueError, match="require_auth cannot be combined"):
        decorator.require_auth("bearer", verifier=lambda r, k: True)(decorated)

    assert route_config.auth_required is None
    assert route_config.auth_verifier is None
    assert route_config.authorization_header_required == "bearer"


def test_api_key_auth_after_presence_only_raises_and_changes_nothing() -> None:
    decorator = _decorator()

    def route() -> None:
        pass

    decorated = decorator.require_authorization_header("bearer")(route)
    route_config = decorator.get_route_config(get_route_id(decorated))
    assert route_config is not None

    with pytest.raises(ValueError, match="api_key_auth cannot be combined"):
        decorator.api_key_auth("X-Key", verifier=lambda r, k: True)(decorated)

    assert route_config.api_key_required is False
    assert route_config.api_key_header is None
    assert route_config.api_key_verifier is None
    assert dict(route_config.required_headers) == {}


@pytest.mark.parametrize(
    "first",
    [
        lambda d: d.require_auth("bearer", verifier=lambda r, k: True),
        lambda d: d.api_key_auth("X-Key", verifier=lambda r, k: True),
    ],
)
def test_presence_only_after_an_authenticated_route_raises_and_changes_nothing(
    first: Callable[[SecurityDecorator], Any],
) -> None:
    decorator = _decorator()

    def route() -> None:
        pass

    decorated = first(decorator)(route)
    route_config = decorator.get_route_config(get_route_id(decorated))
    assert route_config is not None

    with pytest.raises(ValueError, match="require_authorization_header cannot"):
        decorator.require_authorization_header("bearer")(decorated)

    assert route_config.authorization_header_required is None
