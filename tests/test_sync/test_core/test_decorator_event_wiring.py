import logging
from typing import Any
from unittest.mock import MagicMock, patch

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.behavioral.context import BehavioralContext
from guard_core.sync.core.behavioral.processor import BehavioralProcessor
from guard_core.sync.core.checks.factory import build_default_pipeline
from guard_core.sync.core.events.event_types import EventFilter
from guard_core.sync.core.events.middleware_events import SecurityEventBus
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.core.routing.context import RoutingContext
from guard_core.sync.core.routing.resolver import RouteConfigResolver
from guard_core.sync.decorators import SecurityDecorator
from guard_core.sync.handlers.cloud_handler import cloud_handler
from guard_core.sync.handlers.ratelimit_handler import rate_limit_handler
from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler
from tests.test_sync.conftest import SyncMockGuardRequest

_LOGGER = logging.getLogger("test_decorator_event_wiring")


class _RecordingAgent:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def send_event(self, event: Any) -> None:
        self.events.append(event)

    def initialize_redis(self, redis_handler: Any) -> None:
        return None


def _config(**overrides: Any) -> SyncSecurityConfig:
    fields: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_ip_banning": False,
        "enable_rate_limiting": False,
    }
    fields.update(overrides)
    return SyncSecurityConfig(**fields)


def _build_middleware(
    config: SyncSecurityConfig,
    decorator: SecurityDecorator,
    geo_ip_handler: Any = None,
) -> MagicMock:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = _LOGGER
    middleware.event_bus = SecurityEventBus(
        agent_handler=None, config=config, event_filter=EventFilter()
    )
    middleware.create_error_response = MagicMock(
        side_effect=lambda status_code, default_message: MagicMock(
            status_code=status_code
        )
    )
    middleware.guard_decorator = decorator
    middleware.route_resolver = RouteConfigResolver(
        RoutingContext(config=config, logger=_LOGGER, guard_decorator=decorator)
    )
    middleware.geo_ip_handler = geo_ip_handler
    middleware.agent_handler = None
    middleware.rate_limit_handler = rate_limit_handler(config)
    middleware.suspicious_request_counts = {}
    middleware.last_cloud_ip_refresh = 0
    middleware.refresh_cloud_ip_ranges = MagicMock()
    return middleware


def _geo_ip_handler(country: str) -> MagicMock:
    handler = MagicMock(spec=SyncGeoIPHandler)
    handler.get_country.return_value = country
    return handler


def _decorated_route(decorator: SecurityDecorator, apply: Any, name: str) -> str:
    def endpoint() -> str:
        return "ok"

    endpoint.__name__ = name
    endpoint.__qualname__ = name
    endpoint.__module__ = __name__

    decorated = apply(decorator)(endpoint)
    route_id: str = decorated._guard_route_id
    return route_id


def test_require_ip_route_block_wires_send_access_denied_event() -> None:
    config = _config()
    decorator = SecurityDecorator(config)
    recording_agent = _RecordingAgent()
    decorator.initialize_agent(recording_agent)

    route_id = _decorated_route(
        decorator,
        lambda d: d.require_ip(whitelist=["10.0.0.1"]),
        "require_ip_route",
    )
    middleware = _build_middleware(config, decorator)
    pipeline = build_default_pipeline(middleware)

    request = SyncMockGuardRequest(client_host="203.0.113.50")
    request.state.guard_route_id = route_id

    result = pipeline.execute(request)

    assert result is not None
    assert len(recording_agent.events) == 1
    event = recording_agent.events[0]
    assert event.event_type == "access_denied"
    assert event.action_taken == "blocked"
    assert event.decorator_type == "access_control"
    assert event.metadata["violation_type"] == "ip_restriction"


def test_require_auth_failure_wires_send_authentication_failed_event() -> None:
    config = _config()
    decorator = SecurityDecorator(config)
    recording_agent = _RecordingAgent()
    decorator.initialize_agent(recording_agent)

    route_id = _decorated_route(
        decorator, lambda d: d.require_auth(), "require_auth_route"
    )
    middleware = _build_middleware(config, decorator)
    pipeline = build_default_pipeline(middleware)

    request = SyncMockGuardRequest(client_host="203.0.113.51", headers={})
    request.state.guard_route_id = route_id

    result = pipeline.execute(request)

    assert result is not None
    assert len(recording_agent.events) == 1
    event = recording_agent.events[0]
    assert event.event_type == "authentication_failed"
    assert event.action_taken == "blocked"
    assert event.decorator_type == "authentication"
    assert event.metadata["auth_type"] == "bearer"


def test_route_rate_limit_wires_send_rate_limit_event() -> None:
    config = _config(enable_rate_limiting=True)
    decorator = SecurityDecorator(config)
    recording_agent = _RecordingAgent()
    decorator.initialize_agent(recording_agent)

    route_id = _decorated_route(
        decorator, lambda d: d.rate_limit(1, window=60), "rate_limit_route"
    )
    middleware = _build_middleware(config, decorator)
    pipeline = build_default_pipeline(middleware)

    request = SyncMockGuardRequest(client_host="203.0.113.52")
    request.state.guard_route_id = route_id

    assert pipeline.execute(request) is None
    result = pipeline.execute(request)

    assert result is not None
    assert len(recording_agent.events) == 1
    event = recording_agent.events[0]
    assert event.event_type == "rate_limited"
    assert event.action_taken == "blocked"
    assert event.decorator_type == "rate_limiting"
    assert event.metadata["limit"] == 1
    assert event.metadata["window"] == 60


def test_custom_validation_block_wires_generic_send_decorator_event() -> None:
    config = _config()
    decorator = SecurityDecorator(config)
    recording_agent = _RecordingAgent()
    decorator.initialize_agent(recording_agent)

    def _blocking_validator(request: Any) -> Any:
        from tests.test_sync.conftest import MockGuardResponse

        return MockGuardResponse("blocked", 418)

    route_id = _decorated_route(
        decorator,
        lambda d: d.custom_validation(_blocking_validator),
        "custom_validation_route",
    )
    middleware = _build_middleware(config, decorator)
    pipeline = build_default_pipeline(middleware)

    request = SyncMockGuardRequest(client_host="203.0.113.53")
    request.state.guard_route_id = route_id

    result = pipeline.execute(request)

    assert result is not None
    assert len(recording_agent.events) == 1
    event = recording_agent.events[0]
    assert event.event_type == "decorator_violation"
    assert event.action_taken == "request_blocked"
    assert event.decorator_type == "content_filtering"
    assert event.metadata["violation_type"] == "custom_validation"


def _usage_violation_events(config: SyncSecurityConfig) -> list[Any]:
    decorator = SecurityDecorator(config)
    recording_agent = _RecordingAgent()
    decorator.initialize_agent(recording_agent)

    route_id = _decorated_route(
        decorator,
        lambda d: d.usage_monitor(max_calls=1, window=60, action="log"),
        "usage_monitor_route",
    )
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None

    context = BehavioralContext(
        config=config,
        logger=_LOGGER,
        event_bus=SecurityEventBus(
            agent_handler=recording_agent,
            config=config,
            event_filter=EventFilter(
                muted_event_types=frozenset(config.muted_event_types)
            ),
        ),
        guard_decorator=decorator,
    )
    processor = BehavioralProcessor(context)

    for _ in range(2):
        request = SyncMockGuardRequest(client_host="203.0.113.54")
        request.state.guard_route_id = route_id
        request.state.guard_endpoint_id = "usage_monitor_route"
        processor.process_usage_rules(request, "203.0.113.54", route_config)
    return list(recording_agent.events)


def test_usage_monitor_threshold_sends_both_violation_events() -> None:
    events = _usage_violation_events(_config())
    assert [event.event_type for event in events] == [
        "decorator_violation",
        "behavioral_violation",
    ]
    assert events[0].action_taken == "blocked"
    assert events[0].decorator_type == "usage"
    assert events[1].action_taken == "log"
    assert events[1].rule_type == "usage"
    assert "threshold exceeded" in events[0].reason


def test_usage_monitor_threshold_honors_agent_enable_events() -> None:
    assert _usage_violation_events(_config(agent_enable_events=False)) == []


def test_startup_wires_initialize_behavior_tracking_for_a_decorated_route() -> None:
    config = _config()
    decorator = SecurityDecorator(config)
    _decorated_route(
        decorator,
        lambda d: d.usage_monitor(max_calls=5, window=60, action="log"),
        "behavior_tracking_startup_route",
    )

    mock_redis_handler = MagicMock()
    mock_redis_handler.initialize = MagicMock()

    initializer = HandlerInitializer(
        config=config,
        redis_handler=mock_redis_handler,
        guard_decorator=decorator,
    )
    config.enable_redis = True

    with (
        patch("guard_core.sync.handlers.cloud_handler.cloud_handler") as mock_cloud,
        patch("guard_core.sync.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
        patch(
            "guard_core.sync.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_sus,
    ):
        mock_cloud.initialize_redis = MagicMock()
        mock_ipban.initialize_redis = MagicMock()
        mock_sus.initialize_redis = MagicMock()

        initializer.initialize_redis_handlers()

    assert decorator.behavior_tracker.redis_handler is mock_redis_handler


def test_decorator_event_respects_agent_enable_events_gate() -> None:
    config = _config(agent_enable_events=False)
    decorator = SecurityDecorator(config)
    recording_agent = _RecordingAgent()
    decorator.initialize_agent(recording_agent)

    route_id = _decorated_route(
        decorator,
        lambda d: d.require_ip(whitelist=["10.0.0.1"]),
        "gate_disabled_route",
    )
    middleware = _build_middleware(config, decorator)
    pipeline = build_default_pipeline(middleware)

    request = SyncMockGuardRequest(client_host="203.0.113.70")
    request.state.guard_route_id = route_id

    result = pipeline.execute(request)

    assert result is not None
    assert recording_agent.events == []


def test_decorator_event_carries_country_from_geo_ip_handler() -> None:
    config = _config()
    decorator = SecurityDecorator(config)
    recording_agent = _RecordingAgent()
    decorator.initialize_agent(recording_agent, geo_ip_handler=_geo_ip_handler("US"))

    route_id = _decorated_route(
        decorator,
        lambda d: d.require_ip(whitelist=["10.0.0.1"]),
        "gate_country_route",
    )
    middleware = _build_middleware(config, decorator)
    pipeline = build_default_pipeline(middleware)

    request = SyncMockGuardRequest(client_host="203.0.113.71")
    request.state.guard_route_id = route_id

    result = pipeline.execute(request)

    assert result is not None
    assert len(recording_agent.events) == 1
    assert recording_agent.events[0].country == "US"


def test_route_block_countries_wires_send_access_denied_event() -> None:
    config = _config(ipinfo_token="test-token")
    decorator = SecurityDecorator(config)
    recording_agent = _RecordingAgent()
    decorator.initialize_agent(recording_agent)

    route_id = _decorated_route(
        decorator,
        lambda d: d.block_countries(["CN"]),
        "block_countries_route",
    )
    geo_ip_handler = _geo_ip_handler("CN")
    middleware = _build_middleware(config, decorator, geo_ip_handler=geo_ip_handler)
    pipeline = build_default_pipeline(middleware)

    request = SyncMockGuardRequest(client_host="203.0.113.72")
    request.state.guard_route_id = route_id

    result = pipeline.execute(request)

    assert result is not None
    assert len(recording_agent.events) == 1
    event = recording_agent.events[0]
    assert event.event_type == "access_denied"
    assert event.decorator_type == "block_countries"
    assert event.metadata["violation_type"] == "country_restriction"


def test_route_allow_countries_mismatch_wires_send_access_denied_event() -> None:
    config = _config(ipinfo_token="test-token")
    decorator = SecurityDecorator(config)
    recording_agent = _RecordingAgent()
    decorator.initialize_agent(recording_agent)

    route_id = _decorated_route(
        decorator,
        lambda d: d.allow_countries(["US"]),
        "allow_countries_route",
    )
    geo_ip_handler = _geo_ip_handler("CN")
    middleware = _build_middleware(config, decorator, geo_ip_handler=geo_ip_handler)
    pipeline = build_default_pipeline(middleware)

    request = SyncMockGuardRequest(client_host="203.0.113.73")
    request.state.guard_route_id = route_id

    result = pipeline.execute(request)

    assert result is not None
    assert len(recording_agent.events) == 1
    event = recording_agent.events[0]
    assert event.event_type == "access_denied"
    assert event.decorator_type == "allow_countries"
    assert event.metadata["violation_type"] == "country_restriction"


def test_global_country_block_does_not_wire_a_decorator_event() -> None:
    geo_ip_handler = _geo_ip_handler("CN")
    config = _config(blocked_countries=["CN"], geo_ip_handler=geo_ip_handler)
    decorator = SecurityDecorator(config)
    recording_agent = _RecordingAgent()
    decorator.initialize_agent(recording_agent)

    middleware = _build_middleware(config, decorator, geo_ip_handler=geo_ip_handler)
    pipeline = build_default_pipeline(middleware)

    request = SyncMockGuardRequest(client_host="203.0.113.74")

    result = pipeline.execute(request)

    assert result is not None
    assert recording_agent.events == []


def test_route_block_clouds_wires_send_access_denied_event() -> None:
    config = _config()
    decorator = SecurityDecorator(config)
    recording_agent = _RecordingAgent()
    decorator.initialize_agent(recording_agent)

    route_id = _decorated_route(
        decorator,
        lambda d: d.block_clouds(["AWS"]),
        "block_clouds_route",
    )
    middleware = _build_middleware(config, decorator)
    pipeline = build_default_pipeline(middleware)

    request = SyncMockGuardRequest(client_host="3.0.0.9")
    request.state.guard_route_id = route_id

    with (
        patch.object(cloud_handler, "schedule_refresh", MagicMock(return_value=True)),
        patch.object(cloud_handler, "is_cloud_ip", return_value=True),
        patch.object(cloud_handler, "get_cloud_provider_details", return_value=None),
    ):
        result = pipeline.execute(request)

    assert result is not None
    assert len(recording_agent.events) == 1
    event = recording_agent.events[0]
    assert event.event_type == "access_denied"
    assert event.decorator_type == "block_clouds"
    assert event.metadata["violation_type"] == "cloud_provider"
    assert event.metadata["blocked_providers"] == ["AWS"]


def test_global_block_clouds_does_not_wire_a_decorator_event() -> None:
    config = _config(block_cloud_providers=frozenset({"AWS"}))
    decorator = SecurityDecorator(config)
    recording_agent = _RecordingAgent()
    decorator.initialize_agent(recording_agent)

    middleware = _build_middleware(config, decorator)
    pipeline = build_default_pipeline(middleware)

    request = SyncMockGuardRequest(client_host="3.0.0.9")

    with (
        patch.object(cloud_handler, "schedule_refresh", MagicMock(return_value=True)),
        patch.object(cloud_handler, "is_cloud_ip", return_value=True),
        patch.object(cloud_handler, "get_cloud_provider_details", return_value=None),
    ):
        result = pipeline.execute(request)

    assert result is not None
    assert recording_agent.events == []
