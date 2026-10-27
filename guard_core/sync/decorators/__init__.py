from guard_core.sync.decorators.access_control import AccessControlMixin
from guard_core.sync.decorators.advanced import AdvancedMixin
from guard_core.sync.decorators.authentication import AuthenticationMixin
from guard_core.sync.decorators.base import (
    BaseSecurityDecorator,
    BaseSecurityMixin,
    GuardedCallable,
    GuardedParams,
    GuardedReturn,
    RouteConfig,
    get_route_decorator_config,
    get_route_id,
)
from guard_core.sync.decorators.behavioral import BehavioralMixin
from guard_core.sync.decorators.content_filtering import ContentFilteringMixin
from guard_core.sync.decorators.rate_limiting import RateLimitingMixin


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
    "GuardedParams",
    "GuardedReturn",
    "BaseSecurityDecorator",
    "BaseSecurityMixin",
    "AccessControlMixin",
    "RateLimitingMixin",
    "BehavioralMixin",
    "AuthenticationMixin",
    "ContentFilteringMixin",
    "AdvancedMixin",
]
