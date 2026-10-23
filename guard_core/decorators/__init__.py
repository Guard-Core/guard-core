from guard_core.decorators.access_control import AccessControlMixin
from guard_core.decorators.advanced import AdvancedMixin
from guard_core.decorators.authentication import AuthenticationMixin
from guard_core.decorators.base import (
    BaseSecurityDecorator,
    BaseSecurityMixin,
    GuardedCallable,
    RouteConfig,
    get_route_decorator_config,
    get_route_id,
)
from guard_core.decorators.behavioral import BehavioralMixin
from guard_core.decorators.content_filtering import ContentFilteringMixin
from guard_core.decorators.rate_limiting import RateLimitingMixin


class SecurityDecorator(
    BaseSecurityDecorator,
    AccessControlMixin,
    RateLimitingMixin,
    BehavioralMixin,
    AuthenticationMixin,
    ContentFilteringMixin,
    AdvancedMixin,
):
    pass


__all__ = [
    "SecurityDecorator",
    "RouteConfig",
    "get_route_decorator_config",
    "get_route_id",
    "GuardedCallable",
    "BaseSecurityDecorator",
    "BaseSecurityMixin",
    "AccessControlMixin",
    "RateLimitingMixin",
    "BehavioralMixin",
    "AuthenticationMixin",
    "ContentFilteringMixin",
    "AdvancedMixin",
]
