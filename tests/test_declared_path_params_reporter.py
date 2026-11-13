import logging
from collections.abc import Collection
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core._misconfiguration import report_declared_path_param_problems
from guard_core._misconfiguration_kinds import Problem
from guard_core._utils.route_gate import detection_exclusion_path_param_problems
from guard_core.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.decorators.base import RouteConfig
from guard_core.exceptions import MisconfigurationError
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest, declare_route

LOGGER = "guard_core.models"


def _config(**fields: object) -> SecurityConfig:
    return SecurityConfig(enable_redis=False, ban_on_hostile_signals=False, **fields)


def _check(config: SecurityConfig) -> SuspiciousActivityCheck:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("test_pipeline_refusal")
    middleware.suspicious_request_counts = {}
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.route_resolver.should_bypass_check = lambda *_: False
    return SuspiciousActivityCheck(middleware)


def _bad_request() -> MockGuardRequest:
    request = MockGuardRequest(path="/items/1")
    declare_route(request, "/items/{id}")
    request.state.client_ip = "203.0.113.41"
    request.state.guard_route_id = "app.item"
    route_config = RouteConfig()
    route_config.excluded_detection_path_params = {"ghost"}
    request.state.route_config = route_config
    return request


async def test_an_adapter_that_checked_first_leaves_the_check_silent(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(fail_on_misconfiguration=False)
    caplog.set_level(logging.WARNING, logger=LOGGER)
    problems = detection_exclusion_path_param_problems(
        "app.item", "/items/{id}", ["ghost"]
    )

    report_declared_path_param_problems(
        config, problems, logger=logging.getLogger(LOGGER), stacklevel=1
    )
    await _check(config).check(_bad_request())

    logged = [r for r in caplog.records if "@detection_exclusion" in r.getMessage()]
    assert len(logged) == 1


async def test_with_the_flag_on_a_reported_problem_still_raises() -> None:
    config = _config(fail_on_misconfiguration=True)
    problems = detection_exclusion_path_param_problems(
        "app.item", "/items/{id}", ["ghost"]
    )
    log = logging.getLogger(LOGGER)

    for _ in range(2):
        with pytest.raises(MisconfigurationError):
            report_declared_path_param_problems(
                config, problems, logger=log, stacklevel=1
            )


async def test_the_helper_runs_once_per_route_however_many_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import guard_core._utils.route_gate as route_gate

    calls: list[str] = []
    real = route_gate.detection_exclusion_path_param_problems

    def counting(
        route_id: str, template: str, declared: Collection[str]
    ) -> list[Problem]:
        calls.append(route_id)
        return real(route_id, template, declared)

    monkeypatch.setattr(route_gate, "detection_exclusion_path_param_problems", counting)
    check = _check(_config(fail_on_misconfiguration=False))

    for _ in range(5):
        await check.check(_bad_request())

    assert calls == ["app.item"]


def test_the_per_app_cache_is_bounded() -> None:
    import guard_core._misconfiguration as module

    config = _config(fail_on_misconfiguration=False)
    cap = module._DECLARED_PROBLEMS_CAP

    for index in range(cap + 1):
        module.declared_path_problems_of(
            config, f"route.{index}", "/items/{id}", ["ghost"]
        )

    assert len(module._declared_problems_found.for_app(config)) == 1
