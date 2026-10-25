from guard_core.decorators import get_route_id
from guard_core.decorators.access_control import AccessControlMixin
from guard_core.decorators.advanced import AdvancedMixin
from guard_core.decorators.authentication import AuthenticationMixin
from guard_core.decorators.base import BaseSecurityDecorator
from guard_core.decorators.behavioral import BehavioralMixin
from guard_core.decorators.content_filtering import ContentFilteringMixin
from guard_core.decorators.rate_limiting import RateLimitingMixin
from guard_core.models import SecurityConfig


class _AsyncComposedDecorator(
    BaseSecurityDecorator,
    AccessControlMixin,
    AdvancedMixin,
    AuthenticationMixin,
    BehavioralMixin,
    ContentFilteringMixin,
    RateLimitingMixin,
):
    pass


def _async_decorator() -> _AsyncComposedDecorator:
    return _AsyncComposedDecorator(
        SecurityConfig(enable_redis=False, ipinfo_token="test-token")
    )


def _block_target() -> None:
    pass


def _allow_target() -> None:
    pass


async def test_block_countries_uppercases_lowercase_input() -> None:
    d = _async_decorator()
    decorated = d.block_countries(["us", "ca", "Mx"])(_block_target)
    rc = d.get_route_config(get_route_id(decorated))
    assert rc is not None
    assert rc.blocked_countries == ["US", "CA", "MX"]


async def test_allow_countries_uppercases_lowercase_input() -> None:
    d = _async_decorator()
    decorated = d.allow_countries(["br", "ar", "Cl"])(_allow_target)
    rc = d.get_route_config(get_route_id(decorated))
    assert rc is not None
    assert rc.whitelist_countries == ["BR", "AR", "CL"]
