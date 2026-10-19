import logging
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.models import DynamicRules, SecurityConfig
from guard_core.sync.core.checks.factory import build_default_pipeline
from guard_core.sync.core.checks.implementations.emergency_mode import (
    EmergencyModeCheck,
)
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
from guard_core.sync.core.routing.context import RoutingContext
from guard_core.sync.core.routing.resolver import RouteConfigResolver
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from tests.test_sync.conftest import MockGuardResponse, SyncMockGuardRequest

_LOGGER = logging.getLogger("test_emergency_lockdown_covers_excluded_paths")
OUTSIDER = "203.0.113.5"
OPERATOR = "198.51.100.7"


def _config(**overrides: Any) -> SecurityConfig:
    fields: dict[str, Any] = {
        "enable_redis": False,
        "emergency_mode": True,
        "emergency_whitelist": [OPERATOR],
        "exclude_paths": ["/ping", "/docs", "/openapi.json"],
    }
    fields.update(overrides)
    return SecurityConfig(**fields)


def _middleware(config: SecurityConfig) -> MagicMock:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = _LOGGER
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(
        side_effect=lambda status_code, default_message: MockGuardResponse(
            default_message, status_code
        )
    )
    middleware.guard_decorator = None
    middleware.route_resolver = RouteConfigResolver(
        RoutingContext(config=config, logger=_LOGGER, guard_decorator=None)
    )
    middleware.agent_handler = None
    return middleware


def _status(
    config: SecurityConfig, path: str, ip: str, *, excluded: bool = True
) -> int | None:
    middleware = _middleware(config)
    pipeline = (
        build_default_pipeline(middleware)
        if excluded
        else SecurityCheckPipeline([EmergencyModeCheck(middleware)])
    )
    request = SyncMockGuardRequest(path=path, client_host=ip)
    request.state.client_ip = ip
    request.state.guard_exclusion_scoped = excluded
    response = pipeline.execute(request)
    return None if response is None else response.status_code


@pytest.mark.parametrize("path", ["/ping", "/docs", "/openapi.json"])
def test_an_outsider_gets_503_on_every_excluded_path(path: str) -> None:
    assert _status(_config(), path, OUTSIDER) == 503


def test_an_outsider_gets_503_on_a_path_that_is_not_excluded() -> None:
    assert _status(_config(), "/api", OUTSIDER, excluded=False) == 503


@pytest.mark.parametrize("path", ["/ping", "/docs"])
def test_an_emergency_whitelisted_client_passes_on_excluded_paths(
    path: str,
) -> None:
    assert _status(_config(), path, OPERATOR) is None


def test_loopback_is_never_exempted_automatically() -> None:
    assert _status(_config(), "/ping", "127.0.0.1") == 503


def test_an_exempt_path_stays_open_to_an_outsider() -> None:
    config = _config(emergency_exempt_paths=["/ping"])

    assert _status(config, "/ping", OUTSIDER) is None
    assert _status(config, "/docs", OUTSIDER) == 503


def test_an_exempt_path_covers_its_subtree_on_a_non_excluded_path() -> None:
    config = _config(emergency_exempt_paths=["/probe"])

    assert _status(config, "/probe/ready", OUTSIDER, excluded=False) is None
    assert _status(config, "/probes", OUTSIDER, excluded=False) == 503


def test_a_path_with_a_routing_anomaly_is_never_exempt() -> None:
    config = _config(emergency_exempt_paths=["/ping"])

    assert _status(config, "/ping/../api", OUTSIDER, excluded=False) == 503
    assert _status(config, "/ping/%2e%2e/api", OUTSIDER, excluded=False) == 503


def test_passive_mode_logs_and_admits_on_an_excluded_path() -> None:
    assert _status(_config(passive_mode=True), "/ping", OUTSIDER) is None


def test_the_exempt_list_defaults_to_empty() -> None:
    assert SecurityConfig().emergency_exempt_paths == []


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        record.getMessage()
        for record in caplog.records
        if record.levelno == logging.WARNING and "emergency_exempt_paths" in record.msg
    ]


def test_a_static_emergency_config_names_each_unexempted_probe_path_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        _config(exclude_paths=["/ping", "/docs", "/healthz", "/api/ready"])

    messages = _warnings(caplog)
    assert len(messages) == 1
    for named in ("/ping", "/healthz", "/api/ready"):
        assert named in messages[0]
    assert "/docs" not in messages[0]


def test_no_warning_when_every_probe_path_is_exempt(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        _config(emergency_exempt_paths=["/ping"])

    assert _warnings(caplog) == []


def test_no_warning_when_emergency_mode_is_off(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        _config(emergency_mode=False)

    assert _warnings(caplog) == []


def test_a_dynamic_emergency_rule_names_the_unexempted_probe_path(
    caplog: pytest.LogCaptureFixture,
) -> None:
    DynamicRuleManager._instance = None
    config = SecurityConfig(enable_redis=False, exclude_paths=["/ping", "/docs"])
    manager = DynamicRuleManager(config)
    rules = DynamicRules(
        rule_id="R",
        version=1,
        timestamp=datetime.now(timezone.utc),
        emergency_mode=True,
    )

    with caplog.at_level(logging.WARNING):
        manager._apply_rules(rules)

    DynamicRuleManager._instance = None
    messages = _warnings(caplog)
    assert len(messages) == 1
    assert "/ping" in messages[0]
    assert "/docs" not in messages[0]


@pytest.mark.parametrize("entry", ["/", "//", "/%2f", "/%ff"])
def test_an_entry_that_exempts_everything_or_nothing_is_rejected(entry: str) -> None:
    with pytest.raises(ValueError, match="emergency_exempt_paths"):
        SecurityConfig(enable_redis=False, emergency_exempt_paths=[entry])


def test_a_non_list_is_rejected_on_assignment() -> None:
    config = SecurityConfig(enable_redis=False)
    field = "emergency_exempt_paths"

    with pytest.raises(ValueError, match="emergency_exempt_paths must be a list"):
        setattr(config, field, "/ping")
