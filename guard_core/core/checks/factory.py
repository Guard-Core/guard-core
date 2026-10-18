from collections.abc import Collection
from typing import TYPE_CHECKING

from guard_core.core.checks.base import SecurityCheck
from guard_core.core.checks.implementations import (
    AuthenticationCheck,
    CloudIpRefreshCheck,
    CloudProviderCheck,
    CorsPreflightCheck,
    CustomRequestCheck,
    CustomValidatorsCheck,
    EmergencyModeCheck,
    HttpsEnforcementCheck,
    IpSecurityCheck,
    RateLimitCheck,
    ReferrerCheck,
    RequestLoggingCheck,
    RequestSizeContentCheck,
    RequiredHeadersCheck,
    RouteConfigCheck,
    SuspiciousActivityCheck,
    TimeWindowCheck,
    UserAgentCheck,
)
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.decorators.base import RouteConfig

if TYPE_CHECKING:
    from guard_core.protocols.middleware_protocol import GuardMiddlewareProtocol

DEFAULT_CHECK_CLASSES: tuple[type[SecurityCheck], ...] = (
    RouteConfigCheck,
    EmergencyModeCheck,
    HttpsEnforcementCheck,
    RequestLoggingCheck,
    RequestSizeContentCheck,
    CloudIpRefreshCheck,
    IpSecurityCheck,
    CloudProviderCheck,
    UserAgentCheck,
    CorsPreflightCheck,
    RateLimitCheck,
    RequiredHeadersCheck,
    AuthenticationCheck,
    ReferrerCheck,
    CustomValidatorsCheck,
    TimeWindowCheck,
    SuspiciousActivityCheck,
    CustomRequestCheck,
)

WATCHED_CONTAINER_FIELDS: tuple[str, ...] = tuple(
    dict.fromkeys(
        field for cls in DEFAULT_CHECK_CLASSES for field in cls.container_fields
    )
)


def _collect_route_configs(
    middleware: "GuardMiddlewareProtocol",
) -> Collection[RouteConfig] | None:
    decorator = getattr(middleware, "guard_decorator", None)
    if decorator is None:
        return None
    return tuple(decorator._route_configs.values())


def _route_config_revision(middleware: "GuardMiddlewareProtocol") -> int | None:
    decorator = getattr(middleware, "guard_decorator", None)
    if decorator is None:
        return None
    revision: int = decorator.route_config_revision
    return revision


def _build_checks(
    middleware: "GuardMiddlewareProtocol",
) -> list[SecurityCheck]:
    config = middleware.config
    route_configs = _collect_route_configs(middleware)
    return [
        cls(middleware)
        for cls in DEFAULT_CHECK_CLASSES
        if cls.applies_to(config, route_configs)
    ]


def build_default_pipeline(
    middleware: "GuardMiddlewareProtocol",
) -> SecurityCheckPipeline:
    config = middleware.config
    return SecurityCheckPipeline(
        _build_checks(middleware),
        muted_check_logs=config.muted_check_logs,
        config=config,
        rebuild_checks=lambda: _build_checks(middleware),
        watched_container_fields=WATCHED_CONTAINER_FIELDS,
        route_config_revision=lambda: _route_config_revision(middleware),
    )
