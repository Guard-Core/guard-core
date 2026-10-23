import logging
from ipaddress import ip_network
from typing import Any, cast
from unittest.mock import MagicMock, patch

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks import factory
from guard_core.sync.core.checks.factory import build_default_pipeline
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
from guard_core.sync.core.routing.context import RoutingContext
from guard_core.sync.core.routing.resolver import RouteConfigResolver
from guard_core.sync.handlers.cloud_handler import cloud_handler
from tests.test_sync.conftest import MockGuardResponse, SyncMockGuardRequest

_LOGGER = logging.getLogger("test_pipeline_config_revision")


def _blocking_custom_request_check(request: object) -> MockGuardResponse:
    return MockGuardResponse("blocked-by-custom-request-check", 451)


def _neutral_config(**overrides: object) -> SyncSecurityConfig:
    fields: dict[str, object] = {
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
    }
    fields.update(overrides)
    return SyncSecurityConfig(**fields)


def _build_middleware(config: SyncSecurityConfig) -> MagicMock:
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
    decorator = MagicMock()
    decorator._route_configs = {}
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


def test_mutating_config_makes_eliminated_user_agent_check_block() -> None:
    config = _neutral_config()
    middleware = _build_middleware(config)
    pipeline = build_default_pipeline(middleware)
    assert "user_agent" not in pipeline.get_check_names()

    config.blocked_user_agents = ["badbot"]

    request = SyncMockGuardRequest(
        client_host="198.51.100.101",
        headers={"User-Agent": "badbot-scanner"},
    )
    result = pipeline.execute(request)

    assert "user_agent" in pipeline.get_check_names()
    assert result is not None
    assert result.status_code == 403


def test_mutating_config_makes_eliminated_cloud_provider_check_block() -> None:
    config = _neutral_config()
    middleware = _build_middleware(config)
    pipeline = build_default_pipeline(middleware)
    assert "cloud_provider" not in pipeline.get_check_names()

    cloud_handler.ip_ranges["AWS"].add(ip_network("3.0.0.0/8"))
    config.block_cloud_providers = frozenset({"AWS"})

    request = SyncMockGuardRequest(client_host="3.0.0.9")
    with patch.object(cloud_handler, "schedule_refresh", MagicMock(return_value=False)):
        result = pipeline.execute(request)

    assert "cloud_provider" in pipeline.get_check_names()
    assert result is not None
    assert result.status_code == 403


def test_mutating_config_makes_eliminated_custom_request_check_block() -> None:
    config = _neutral_config()
    middleware = _build_middleware(config)
    pipeline = build_default_pipeline(middleware)
    assert "custom_request" not in pipeline.get_check_names()

    config.custom_request_check = cast(Any, _blocking_custom_request_check)

    request = SyncMockGuardRequest(client_host="198.51.100.102")
    result = pipeline.execute(request)

    assert "custom_request" in pipeline.get_check_names()
    assert result is not None
    assert result.status_code == 451


def test_mutating_a_field_no_predicate_reads_does_not_change_composition() -> None:
    config = _neutral_config()
    middleware = _build_middleware(config)

    with patch.object(
        factory, "_build_checks", wraps=factory._build_checks
    ) as rebuild_spy:
        pipeline = build_default_pipeline(middleware)
        before = pipeline.get_check_names()
        rebuild_spy.reset_mock()

        config.custom_log_file = "new-location.log"

        request = SyncMockGuardRequest(client_host="198.51.100.103")
        for _ in range(5):
            pipeline.execute(request)

        assert pipeline.get_check_names() == before
        assert rebuild_spy.call_count == 1


def test_execute_does_not_rebuild_when_config_is_unchanged() -> None:
    config = _neutral_config()
    middleware = _build_middleware(config)

    with patch.object(
        factory, "_build_checks", wraps=factory._build_checks
    ) as rebuild_spy:
        pipeline = build_default_pipeline(middleware)
        rebuild_spy.reset_mock()

        request = SyncMockGuardRequest(client_host="198.51.100.104")
        for _ in range(5):
            pipeline.execute(request)

        rebuild_spy.assert_not_called()


def test_rebuild_swaps_checks_via_new_list_not_in_place_mutation() -> None:
    config = _neutral_config()
    middleware = _build_middleware(config)
    pipeline = build_default_pipeline(middleware)

    snapshot = pipeline.checks
    snapshot_names_before = [check.check_name for check in snapshot]

    config.blocked_user_agents = ["badbot"]
    request = SyncMockGuardRequest(client_host="198.51.100.105")
    pipeline.execute(request)

    assert pipeline.checks is not snapshot
    assert [check.check_name for check in snapshot] == snapshot_names_before


def test_pipeline_built_without_config_never_rebuilds() -> None:
    config = _neutral_config()
    middleware = _build_middleware(config)
    checks = factory._build_checks(middleware)

    pipeline = SecurityCheckPipeline(checks)
    original_checks = pipeline.checks

    config.blocked_user_agents = ["badbot"]
    request = SyncMockGuardRequest(
        client_host="198.51.100.106",
        headers={"User-Agent": "badbot-scanner"},
    )
    result = pipeline.execute(request)

    assert pipeline.checks is original_checks
    assert result is None


def test_appending_blocked_user_agent_in_place_runs_eliminated_check() -> None:
    config = _neutral_config()
    middleware = _build_middleware(config)
    pipeline = build_default_pipeline(middleware)
    assert "user_agent" not in pipeline.get_check_names()

    config.blocked_user_agents.append("badbot")

    request = SyncMockGuardRequest(
        client_host="198.51.100.121",
        headers={"User-Agent": "badbot-scanner"},
    )
    result = pipeline.execute(request)

    assert "user_agent" in pipeline.get_check_names()
    assert result is not None
    assert result.status_code == 403


def test_replacing_blocked_user_agent_in_place_does_not_rebuild() -> None:
    config = _neutral_config(blocked_user_agents=["goodbot"])
    middleware = _build_middleware(config)

    with patch.object(
        factory, "_build_checks", wraps=factory._build_checks
    ) as rebuild_spy:
        pipeline = build_default_pipeline(middleware)
        assert "user_agent" in pipeline.get_check_names()
        rebuild_spy.reset_mock()

        config.blocked_user_agents[0] = "otherbot"

        request = SyncMockGuardRequest(
            client_host="198.51.100.122",
            headers={"User-Agent": "harmless"},
        )
        for _ in range(5):
            pipeline.execute(request)

        rebuild_spy.assert_not_called()


def test_reassigning_block_cloud_providers_runs_eliminated_check() -> None:
    config = _neutral_config(block_cloud_providers=frozenset())
    middleware = _build_middleware(config)
    pipeline = build_default_pipeline(middleware)
    assert "cloud_provider" not in pipeline.get_check_names()

    cloud_handler.ip_ranges["AWS"].add(ip_network("4.0.0.0/8"))
    config.block_cloud_providers = frozenset({"AWS"})

    request = SyncMockGuardRequest(client_host="4.0.0.9")
    with patch.object(cloud_handler, "schedule_refresh", MagicMock(return_value=False)):
        result = pipeline.execute(request)

    assert "cloud_provider" in pipeline.get_check_names()
    assert result is not None
    assert result.status_code == 403


def test_reassigning_block_cloud_providers_rebuilds_every_time() -> None:
    config = _neutral_config(block_cloud_providers=frozenset({"AWS"}))
    middleware = _build_middleware(config)

    with patch.object(
        factory, "_build_checks", wraps=factory._build_checks
    ) as rebuild_spy:
        pipeline = build_default_pipeline(middleware)
        assert "cloud_provider" in pipeline.get_check_names()
        rebuild_spy.reset_mock()

        config.block_cloud_providers = frozenset({"GCP"})

        request = SyncMockGuardRequest(client_host="198.51.100.123")
        with patch.object(
            cloud_handler, "schedule_refresh", MagicMock(return_value=False)
        ):
            pipeline.execute(request)

        rebuild_spy.assert_called_once()


def test_setting_an_endpoint_rate_limit_in_place_makes_eliminated_check_run() -> None:
    config = _neutral_config()
    middleware = _build_middleware(config)
    pipeline = build_default_pipeline(middleware)
    assert "rate_limit" not in pipeline.get_check_names()

    config.endpoint_rate_limits["/x"] = (0, 60)

    request = SyncMockGuardRequest(client_host="198.51.100.124", path="/x")
    pipeline.execute(request)

    assert "rate_limit" in pipeline.get_check_names()


def test_overwriting_an_endpoint_rate_limit_value_in_place_does_not_rebuild() -> None:
    config = _neutral_config(endpoint_rate_limits={"/x": (5, 60)})
    middleware = _build_middleware(config)

    with patch.object(
        factory, "_build_checks", wraps=factory._build_checks
    ) as rebuild_spy:
        pipeline = build_default_pipeline(middleware)
        assert "rate_limit" in pipeline.get_check_names()
        rebuild_spy.reset_mock()

        config.endpoint_rate_limits["/x"] = (1, 30)

        request = SyncMockGuardRequest(client_host="198.51.100.125", path="/x")
        for _ in range(5):
            pipeline.execute(request)

        rebuild_spy.assert_not_called()


@pytest.mark.parametrize("field_name", ["blacklist", "whitelist"])
def test_reassigning_blacklist_or_whitelist_never_flips_any_check_applies_to(
    field_name: str,
) -> None:
    assert field_name not in factory.WATCHED_CONTAINER_FIELDS

    config = SyncSecurityConfig(**{field_name: ()})
    before = {
        cls: cls.applies_to(config, None) for cls in factory.DEFAULT_CHECK_CLASSES
    }

    setattr(config, field_name, ("203.0.113.5",))

    after = {cls: cls.applies_to(config, None) for cls in factory.DEFAULT_CHECK_CLASSES}

    assert before == after
