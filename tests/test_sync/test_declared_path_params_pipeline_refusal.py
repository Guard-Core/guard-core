import logging
from unittest.mock import MagicMock

import pytest

from guard_core._misconfiguration_kinds import MisconfigurationError
from guard_core._parked_records import RELEASE_EPOCH_RECORD
from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
from guard_core.sync.decorators.base import RouteConfig
from tests.test_sync.conftest import SyncMockGuardRequest, declare_route

LOGGER = "guard_core.models"


def _config(**fields: object) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=False, ban_on_hostile_signals=False, **fields
    )


def _check(config: SyncSecurityConfig) -> SuspiciousActivityCheck:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("test_pipeline_refusal")
    middleware.suspicious_request_counts = {}
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.route_resolver.should_bypass_check = lambda *_: False
    return SuspiciousActivityCheck(middleware)


def _bad_request() -> SyncMockGuardRequest:
    request = SyncMockGuardRequest(path="/items/1")
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
def test_the_pipeline_refuses_every_request_with_a_fresh_error(
    fields: dict[str, object],
) -> None:
    config = _config(fail_on_misconfiguration=True, **fields)
    pipeline = SecurityCheckPipeline([_check(config)])
    errors = []

    for _ in range(3):
        with pytest.raises(MisconfigurationError) as refused:
            pipeline.execute(_bad_request())
        errors.append(refused.value)

    assert len({id(error) for error in errors}) == 3
    assert [(p.kind, p.subject) for p in errors[0].problems] == [
        ("decorator.detection_exclusion.param_not_in_template", "ghost")
    ]


def test_a_whitelisted_client_is_refused_too() -> None:
    config = _config(fail_on_misconfiguration=True)
    request = _bad_request()
    request.state.is_whitelisted = True

    with pytest.raises(MisconfigurationError):
        SecurityCheckPipeline([_check(config)]).execute(request)


def test_a_rebuild_error_that_is_a_refusal_reaches_the_host() -> None:
    config = _config(fail_on_misconfiguration=True, fail_secure=False)
    refusal = MisconfigurationError("refused", [])
    pipeline = SecurityCheckPipeline(
        [_check(config)], config=config, reinitialize_app=MagicMock(side_effect=refusal)
    )
    config.__dict__[RELEASE_EPOCH_RECORD] = 1

    with pytest.raises(MisconfigurationError):
        pipeline.execute(SyncMockGuardRequest(path="/plain"))


def test_with_the_flag_off_one_kinded_warning_per_problem_even_after_a_rebuild(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(fail_on_misconfiguration=False)
    caplog.set_level(logging.WARNING, logger=LOGGER)

    for _ in range(2):
        check = _check(config)
        check.check(_bad_request())
        check.check(_bad_request())

    logged = [r for r in caplog.records if "@detection_exclusion" in r.getMessage()]
    assert len(logged) == 1
    assert logged[0].__dict__["problems"] == (
        ("decorator.detection_exclusion.param_not_in_template", "ghost"),
    )
