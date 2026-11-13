import logging
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core._misconfiguration_kinds import MisconfigurationError
from guard_core._parked_records import RELEASE_EPOCH_RECORD
from guard_core.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.decorators.base import RouteConfig
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


@pytest.mark.parametrize(
    "fields",
    [
        {"fail_secure": True},
        {"fail_secure": False},
        {"passive_mode": True},
    ],
    ids=["fail_secure", "fail_open", "passive"],
)
async def test_the_pipeline_refuses_every_request_with_a_fresh_error(
    fields: dict[str, object],
) -> None:
    config = _config(fail_on_misconfiguration=True, **fields)
    pipeline = SecurityCheckPipeline([_check(config)])
    errors = []

    for _ in range(3):
        with pytest.raises(MisconfigurationError) as refused:
            await pipeline.execute(_bad_request())
        errors.append(refused.value)

    assert len({id(error) for error in errors}) == 3
    assert [(p.kind, p.subject) for p in errors[0].problems] == [
        ("decorator.detection_exclusion.param_not_in_template", "ghost")
    ]


async def test_a_whitelisted_client_is_refused_too() -> None:
    config = _config(fail_on_misconfiguration=True)
    request = _bad_request()
    request.state.is_whitelisted = True

    with pytest.raises(MisconfigurationError):
        await SecurityCheckPipeline([_check(config)]).execute(request)


async def test_a_rebuild_error_that_is_a_refusal_reaches_the_host() -> None:
    config = _config(fail_on_misconfiguration=True, fail_secure=False)
    refusal = MisconfigurationError("refused", [])
    pipeline = SecurityCheckPipeline(
        [_check(config)], config=config, reinitialize_app=AsyncMock(side_effect=refusal)
    )
    config.__dict__[RELEASE_EPOCH_RECORD] = 1

    with pytest.raises(MisconfigurationError):
        await pipeline.execute(MockGuardRequest(path="/plain"))


async def test_with_the_flag_off_one_kinded_warning_per_problem_even_after_a_rebuild(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(fail_on_misconfiguration=False)
    caplog.set_level(logging.WARNING, logger=LOGGER)

    for _ in range(2):
        check = _check(config)
        await check.check(_bad_request())
        await check.check(_bad_request())

    logged = [r for r in caplog.records if "@detection_exclusion" in r.getMessage()]
    assert len(logged) == 1
    assert logged[0].__dict__["problems"] == (
        ("decorator.detection_exclusion.param_not_in_template", "ghost"),
    )
