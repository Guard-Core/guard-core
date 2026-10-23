import logging
from unittest.mock import MagicMock, patch

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks import factory
from guard_core.sync.core.checks.factory import build_default_pipeline
from guard_core.sync.core.routing.context import RoutingContext
from guard_core.sync.core.routing.resolver import RouteConfigResolver
from guard_core.sync.decorators.base import BaseSecurityDecorator
from guard_core.sync.handlers.cloud_handler import cloud_handler
from guard_core.sync.handlers.ratelimit_handler import RateLimitBlock
from tests.test_sync.conftest import MockGuardResponse, SyncMockGuardRequest

_LOGGER = logging.getLogger("test_pipeline_route_config_revision")


def _route_a() -> None:
    pass


def _route_b() -> None:
    pass


def _blocking_validator(request: object) -> MockGuardResponse:
    return MockGuardResponse("blocked-by-custom-validator", 418)


def _neutral_config(**overrides: object) -> SyncSecurityConfig:
    fields: dict[str, object] = {
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
    }
    fields.update(overrides)
    return SyncSecurityConfig(**fields)


def _build_middleware(
    config: SyncSecurityConfig, decorator: BaseSecurityDecorator | None
) -> MagicMock:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = _LOGGER
    middleware.event_bus = MagicMock()
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.event_bus.send_cloud_detection_events = MagicMock()
    middleware.create_error_response = MagicMock(
        side_effect=lambda status_code, default_message: MockGuardResponse(
            default_message, status_code
        )
    )
    middleware.response_factory = MagicMock()
    middleware.response_factory.apply_modifier = MagicMock(side_effect=lambda r: r)
    middleware.guard_decorator = decorator
    middleware.route_resolver = RouteConfigResolver(
        RoutingContext(config=config, logger=_LOGGER, guard_decorator=decorator)
    )
    middleware.geo_ip_handler = None
    middleware.agent_handler = None
    middleware.last_cloud_ip_refresh = 0
    middleware.refresh_cloud_ip_ranges = MagicMock()
    middleware.rate_limit_handler = MagicMock()
    middleware.rate_limit_handler.check_rate_limit = MagicMock(return_value=None)
    return middleware


def test_assigning_auth_required_on_existing_route_runs_eliminated_check() -> None:
    config = _neutral_config()
    decorator = BaseSecurityDecorator(config)
    route_config = decorator._ensure_route_config(_route_a)
    route_id = decorator._get_route_id(_route_a)
    middleware = _build_middleware(config, decorator)

    pipeline = build_default_pipeline(middleware)
    assert "authentication" not in pipeline.get_check_names()

    route_config.auth_required = "bearer"

    request = SyncMockGuardRequest(client_host="198.51.100.201")
    request.state.guard_route_id = route_id
    result = pipeline.execute(request)

    assert "authentication" in pipeline.get_check_names()
    assert result is not None
    assert result.status_code == 401


def test_registering_new_route_with_headers_runs_eliminated_headers_check() -> None:
    config = _neutral_config()
    decorator = BaseSecurityDecorator(config)
    middleware = _build_middleware(config, decorator)

    pipeline = build_default_pipeline(middleware)
    assert "required_headers" not in pipeline.get_check_names()

    new_route_config = decorator._ensure_route_config(_route_b)
    new_route_config.required_headers = {"X-Api-Key": "required"}
    route_id = decorator._get_route_id(_route_b)

    request = SyncMockGuardRequest(client_host="198.51.100.202")
    request.state.guard_route_id = route_id
    result = pipeline.execute(request)

    assert "required_headers" in pipeline.get_check_names()
    assert result is not None
    assert result.status_code == 400


def test_appending_custom_validator_in_place_runs_eliminated_check() -> None:
    config = _neutral_config()
    decorator = BaseSecurityDecorator(config)
    route_config = decorator._ensure_route_config(_route_a)
    route_id = decorator._get_route_id(_route_a)
    middleware = _build_middleware(config, decorator)

    pipeline = build_default_pipeline(middleware)
    assert "custom_validators" not in pipeline.get_check_names()

    route_config.custom_validators.append(_blocking_validator)

    request = SyncMockGuardRequest(client_host="198.51.100.203")
    request.state.guard_route_id = route_id
    result = pipeline.execute(request)

    assert "custom_validators" in pipeline.get_check_names()
    assert result is not None
    assert result.status_code == 418


def test_setting_required_header_item_in_place_runs_eliminated_check() -> None:
    config = _neutral_config()
    decorator = BaseSecurityDecorator(config)
    route_config = decorator._ensure_route_config(_route_a)
    route_id = decorator._get_route_id(_route_a)
    middleware = _build_middleware(config, decorator)

    pipeline = build_default_pipeline(middleware)
    assert "required_headers" not in pipeline.get_check_names()

    route_config.required_headers["X-Api-Key"] = "required"

    request = SyncMockGuardRequest(client_host="198.51.100.205")
    request.state.guard_route_id = route_id
    result = pipeline.execute(request)

    assert "required_headers" in pipeline.get_check_names()
    assert result is not None
    assert result.status_code == 400


def test_appending_blocked_user_agent_in_place_runs_eliminated_check() -> None:
    config = _neutral_config()
    decorator = BaseSecurityDecorator(config)
    route_config = decorator._ensure_route_config(_route_a)
    route_id = decorator._get_route_id(_route_a)
    middleware = _build_middleware(config, decorator)

    pipeline = build_default_pipeline(middleware)
    assert "user_agent" not in pipeline.get_check_names()

    route_config.blocked_user_agents.append("badbot")

    request = SyncMockGuardRequest(
        client_host="198.51.100.208", headers={"User-Agent": "badbot-scanner"}
    )
    request.state.guard_route_id = route_id
    result = pipeline.execute(request)

    assert "user_agent" in pipeline.get_check_names()
    assert result is not None
    assert result.status_code == 403


def test_adding_block_cloud_provider_in_place_runs_eliminated_check() -> None:
    config = _neutral_config()
    decorator = BaseSecurityDecorator(config)
    route_config = decorator._ensure_route_config(_route_a)
    route_id = decorator._get_route_id(_route_a)
    middleware = _build_middleware(config, decorator)

    pipeline = build_default_pipeline(middleware)
    assert "cloud_provider" not in pipeline.get_check_names()

    route_config.block_cloud_providers.add("AWS")

    with patch.object(cloud_handler, "is_cloud_ip", return_value=True):
        request = SyncMockGuardRequest(client_host="3.0.0.9")
        request.state.guard_route_id = route_id
        result = pipeline.execute(request)

    assert "cloud_provider" in pipeline.get_check_names()
    assert result is not None
    assert result.status_code == 403


def test_updating_geo_rate_limit_in_place_runs_eliminated_check() -> None:
    config = _neutral_config()
    config.geo_ip_handler = MagicMock(get_country=MagicMock(return_value=None))
    decorator = BaseSecurityDecorator(config)
    route_config = decorator._ensure_route_config(_route_a)
    route_config.geo_rate_limits = {}
    route_id = decorator._get_route_id(_route_a)
    middleware = _build_middleware(config, decorator)
    middleware.geo_ip_handler = config.geo_ip_handler
    middleware.rate_limit_handler.report_rate_limit_block = MagicMock()
    middleware.rate_limit_handler.check_rate_limit_tiers = MagicMock(
        return_value=RateLimitBlock(0, 1, MockGuardResponse("rate-limited", 429))
    )

    pipeline = build_default_pipeline(middleware)
    assert "rate_limit" not in pipeline.get_check_names()

    route_config.geo_rate_limits["*"] = (0, 60)

    request = SyncMockGuardRequest(client_host="198.51.100.209")
    request.state.guard_route_id = route_id
    result = pipeline.execute(request)

    assert "rate_limit" in pipeline.get_check_names()
    assert result is not None
    assert result.status_code == 429


def test_mutating_field_no_predicate_reads_does_not_change_composition() -> None:
    config = _neutral_config()
    decorator = BaseSecurityDecorator(config)
    route_config = decorator._ensure_route_config(_route_a)
    route_id = decorator._get_route_id(_route_a)
    middleware = _build_middleware(config, decorator)

    with patch.object(
        factory, "_build_checks", wraps=factory._build_checks
    ) as rebuild_spy:
        pipeline = build_default_pipeline(middleware)
        before = pipeline.get_check_names()
        rebuild_spy.reset_mock()

        route_config.rate_limit_window = 120

        request = SyncMockGuardRequest(client_host="198.51.100.204")
        request.state.guard_route_id = route_id
        for _ in range(5):
            pipeline.execute(request)

        assert pipeline.get_check_names() == before
        assert rebuild_spy.call_count == 1


def test_execute_does_not_rebuild_when_route_configs_are_unchanged() -> None:
    config = _neutral_config()
    decorator = BaseSecurityDecorator(config)
    decorator._ensure_route_config(_route_a)
    route_id = decorator._get_route_id(_route_a)
    middleware = _build_middleware(config, decorator)

    with patch.object(
        factory, "_build_checks", wraps=factory._build_checks
    ) as rebuild_spy:
        pipeline = build_default_pipeline(middleware)
        rebuild_spy.reset_mock()

        request = SyncMockGuardRequest(client_host="198.51.100.206")
        request.state.guard_route_id = route_id
        for _ in range(5):
            pipeline.execute(request)

        rebuild_spy.assert_not_called()


def test_pipeline_without_guard_decorator_never_rebuilds_on_route_changes() -> None:
    config = _neutral_config()
    middleware = _build_middleware(config, decorator=None)

    pipeline = build_default_pipeline(middleware)
    assert "authentication" in pipeline.get_check_names()

    request = SyncMockGuardRequest(client_host="198.51.100.207")
    result = pipeline.execute(request)

    assert result is None
