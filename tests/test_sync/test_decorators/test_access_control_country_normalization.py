from guard_core.models import SyncSecurityConfig
from guard_core.sync.decorators.access_control import AccessControlMixin
from guard_core.sync.decorators.advanced import AdvancedMixin
from guard_core.sync.decorators.authentication import AuthenticationMixin
from guard_core.sync.decorators.base import BaseSecurityDecorator
from guard_core.sync.decorators.behavioral import BehavioralMixin
from guard_core.sync.decorators.content_filtering import ContentFilteringMixin
from guard_core.sync.decorators.rate_limiting import RateLimitingMixin


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
    return _AsyncComposedDecorator(SyncSecurityConfig(enable_redis=False))


def _block_target() -> None:
    pass


def _allow_target() -> None:
    pass


def test_block_countries_uppercases_lowercase_input() -> None:
    d = _async_decorator()
    decorated = d.block_countries(["us", "ca", "Mx"])(_block_target)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert rc.blocked_countries == ["US", "CA", "MX"]


def test_allow_countries_uppercases_lowercase_input() -> None:
    d = _async_decorator()
    decorated = d.allow_countries(["br", "ar", "Cl"])(_allow_target)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert rc.whitelist_countries == ["BR", "AR", "CL"]
