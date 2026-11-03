import logging
import time
from collections.abc import Callable, Collection
from typing import Any
from unittest.mock import MagicMock, Mock

from guard_core.models import SyncSecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.checks.factory import build_default_pipeline
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
from guard_core.sync.core.routing.context import RoutingContext
from guard_core.sync.core.routing.resolver import RouteConfigResolver
from guard_core.sync.decorators import SecurityDecorator
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.handlers.ratelimit_handler import rate_limit_handler
from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from tests.test_sync.conftest import MockGuardResponse, SyncMockGuardRequest


def custom_check(request: SyncGuardRequest) -> GuardResponse | None:
    return None


def custom_validator(request: SyncGuardRequest) -> GuardResponse | None:
    return None


def fully_enabled_route_config() -> RouteConfig:
    route_config = RouteConfig()
    route_config.max_request_size = 1000
    route_config.required_headers = {"X-Api-Key": "required"}
    route_config.auth_required = "bearer"
    route_config.require_referrer = ["example.com"]
    route_config.custom_validators = [custom_validator]
    route_config.time_restrictions = {"start": "00:00", "end": "23:59"}
    return route_config


def fully_enabled_config() -> SyncSecurityConfig:
    return SyncSecurityConfig(
        emergency_mode=True,
        enforce_https=True,
        log_request_level="INFO",
        block_cloud_providers={"AWS"},
        blocked_user_agents=["badbot"],
        custom_request_check=custom_check,
    )


def middleware_for(
    config: SyncSecurityConfig,
    route_configs: Collection[RouteConfig] | None = (),
) -> Mock:
    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.create_error_response = MagicMock(return_value=Mock(status_code=500))
    if route_configs is None:
        middleware.guard_decorator = None
    else:
        decorator = Mock()
        decorator._route_configs = dict(enumerate(route_configs))
        middleware.guard_decorator = decorator
    return middleware


LOGGER = logging.getLogger("pipeline_harness")


def fixed_country_geo_ip(country: str) -> MagicMock:
    geo_ip = MagicMock(spec=SyncGeoIPHandler)
    geo_ip.is_initialized = True
    geo_ip.initialize = MagicMock()
    geo_ip.get_country.return_value = country
    return geo_ip


def build_middleware(
    config: SyncSecurityConfig,
    decorator: SecurityDecorator,
    geo_ip_handler: object = None,
) -> MagicMock:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = LOGGER
    middleware.event_bus = MagicMock()
    middleware.create_error_response = MagicMock(
        side_effect=lambda status_code, default_message: MockGuardResponse(
            default_message, status_code
        )
    )
    middleware.response_factory = MagicMock()
    middleware.response_factory.create_https_redirect = MagicMock(
        side_effect=lambda request: MockGuardResponse("redirect", 301)
    )
    middleware.guard_decorator = decorator
    middleware.route_resolver = RouteConfigResolver(
        RoutingContext(config=config, logger=LOGGER, guard_decorator=decorator)
    )
    middleware.geo_ip_handler = geo_ip_handler
    middleware.agent_handler = None
    middleware.rate_limit_handler = rate_limit_handler(config)
    middleware.suspicious_request_counts = {}
    middleware.last_cloud_ip_refresh = int(time.time())
    return middleware


def build_route_pipeline(
    config: SyncSecurityConfig,
    *decorator_factories: Callable[[SecurityDecorator], Any],
    geo_ip_handler: object = None,
) -> tuple[SecurityCheckPipeline, MagicMock, str]:
    decorator = SecurityDecorator(config)

    def endpoint() -> str:
        return "ok"

    endpoint.__module__ = "pipeline_harness"
    decorated: Any = endpoint
    for factory in reversed(decorator_factories):
        decorated = factory(decorator)(decorated)
    middleware = build_middleware(config, decorator, geo_ip_handler)
    return (
        build_default_pipeline(middleware),
        middleware,
        decorated._guard_route_id,
    )


def send_request(
    pipeline: SecurityCheckPipeline,
    route_id: str,
    *,
    ip: str,
    path: str = "/x",
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    scheme: str = "https",
) -> GuardResponse | None:
    request = SyncMockGuardRequest(
        path=path,
        method=method,
        headers=headers or {},
        client_host=ip,
        scheme=scheme,
        body_content=body,
    )
    request.state.guard_route_id = route_id
    response = pipeline.execute(request)
    return response
