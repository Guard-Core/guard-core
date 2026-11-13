import logging
from typing import Any

import pytest

from guard_core._misconfiguration_kinds import KINDS
from guard_core.exceptions import MisconfigurationError
from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils import route_gate
from guard_core.sync.core.routing.context import RoutingContext
from guard_core.sync.core.routing.resolver import RouteConfigResolver
from guard_core.sync.decorators import SecurityDecorator
from guard_core.sync.handlers import ipban_handler
from tests.test_sync.conftest import SyncMockGuardRequest
from tests.test_sync.test_core.conftest import build_route_pipeline, send_request

_LOGGER = logging.getLogger("pipeline_harness")


def _config(**overrides: object) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        **overrides,
    )


def _pipeline_with_foreign_route(config: SyncSecurityConfig) -> tuple[Any, str]:
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.require_auth("bearer", verifier=lambda r, k: False)
    )
    middleware_decorator = SecurityDecorator(config)
    middleware.guard_decorator = middleware_decorator
    middleware.route_resolver = RouteConfigResolver(
        RoutingContext(
            config=config, logger=_LOGGER, guard_decorator=middleware_decorator
        )
    )
    return pipeline, route_id


KIND = "route.unknown_to_decorator"
FOREIGN_IP = "203.0.113.90"


def _foreign_problems(records: list[logging.LogRecord]) -> list[tuple[str, ...]]:
    return [
        problem
        for record in records
        for problem in record.__dict__.get("problems", ())
        if problem[0] == KIND
    ]


def test_the_kind_is_declared_as_a_runtime_error_naming_the_route() -> None:
    info = KINDS.get(KIND)

    assert info is not None
    assert (info.severity, info.scope, info.subject) == (
        "error",
        "runtime",
        "the route's label",
    )


def test_the_helper_builds_the_kinded_problem_with_the_route_label() -> None:
    assert hasattr(route_gate, "route_unknown_to_decorator_problem")

    problem = route_gate.route_unknown_to_decorator_problem("app.admin")

    assert (problem.kind, problem.subject, problem.severity) == (
        KIND,
        "app.admin",
        "error",
    )
    assert "'app.admin'" in problem
    assert "decorated by a different SecurityDecorator instance" in problem
    assert (
        "than the one the middleware uses, so none of its decorators apply" in problem
    )
    assert (
        "Decorate the route with the SecurityDecorator the middleware uses" in problem
    )


def test_strict_mode_fails_a_route_whose_config_is_unknown_to_the_decorator() -> None:
    pipeline, route_id = _pipeline_with_foreign_route(
        _config(route_resolution_strict=True, fail_on_misconfiguration=False)
    )

    response = send_request(pipeline, route_id, ip=FOREIGN_IP)

    assert response is not None
    assert response.status_code == 500


def test_with_the_flag_on_strict_mode_is_never_reached_for_a_foreign_route() -> None:
    pipeline, route_id = _pipeline_with_foreign_route(
        _config(route_resolution_strict=True, fail_on_misconfiguration=True)
    )

    with pytest.raises(MisconfigurationError) as refused:
        send_request(pipeline, route_id, ip=FOREIGN_IP)

    assert [(p.kind, p.subject) for p in refused.value.problems] == [(KIND, route_id)]


def test_with_the_flag_on_every_request_is_refused_with_a_fresh_error() -> None:
    pipeline, route_id = _pipeline_with_foreign_route(
        _config(fail_on_misconfiguration=True)
    )
    errors = []

    for _ in range(3):
        with pytest.raises(MisconfigurationError) as refused:
            send_request(pipeline, route_id, ip=FOREIGN_IP)
        errors.append(refused.value)

    assert len({id(error) for error in errors}) == 3
    assert all(error.problems[0].kind == KIND for error in errors)


def test_refused_requests_never_ban_the_client() -> None:
    pipeline, route_id = _pipeline_with_foreign_route(
        _config(
            fail_on_misconfiguration=True,
            ban_on_hostile_signals=True,
            auto_ban_threshold=2,
        )
    )

    for _ in range(6):
        with pytest.raises(MisconfigurationError):
            send_request(pipeline, route_id, ip=FOREIGN_IP)

    assert not ipban_handler.ip_ban_manager.is_ip_banned(FOREIGN_IP)


def test_non_strict_mode_passes_but_reports_once_per_route_id(
    caplog: pytest.LogCaptureFixture,
) -> None:
    pipeline, route_id = _pipeline_with_foreign_route(
        _config(fail_on_misconfiguration=False)
    )

    with caplog.at_level(logging.WARNING):
        responses = [send_request(pipeline, route_id, ip=FOREIGN_IP) for _ in range(3)]

    assert responses == [None, None, None]
    assert _foreign_problems(caplog.records) == [(KIND, route_id)]
    reported = [r for r in caplog.records if r.__dict__.get("problems")]
    assert (
        route_gate.route_unknown_to_decorator_problem(route_id)
        in reported[0].getMessage()
    )


def test_a_route_known_to_the_decorator_is_not_reported(
    caplog: pytest.LogCaptureFixture,
) -> None:
    pipeline, _, route_id = build_route_pipeline(
        _config(route_resolution_strict=True),
        lambda d: d.require_auth("bearer", verifier=lambda r, k: True),
    )

    with caplog.at_level(logging.WARNING):
        response = send_request(
            pipeline,
            route_id,
            ip="203.0.113.92",
            headers={"authorization": "Bearer ok"},
        )

    assert response is None
    assert not _foreign_problems(caplog.records)


def test_a_request_without_a_route_id_is_not_reported() -> None:
    pipeline, _, _ = build_route_pipeline(
        _config(route_resolution_strict=True), lambda d: d.rate_limit(5, 60)
    )

    response = send_request(pipeline, "", ip="203.0.113.93")

    assert response is None


def test_two_resolver_calls_per_request_report_a_foreign_route_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(fail_on_misconfiguration=False)
    decorator = SecurityDecorator(config)
    resolver = RouteConfigResolver(
        RoutingContext(config=config, logger=_LOGGER, guard_decorator=decorator)
    )

    with caplog.at_level(logging.WARNING):
        for _ in range(3):
            request = SyncMockGuardRequest(path="/x")
            request.state.guard_route_id = "app.elsewhere"
            assert resolver.get_route_config(request) is None
            assert resolver.get_route_config(request) is None
            assert request.state.guard_route_unresolved is True

    assert _foreign_problems(caplog.records) == [(KIND, "app.elsewhere")]


def test_the_strict_500_for_a_foreign_route_feeds_no_ban_counter() -> None:
    pipeline, route_id = _pipeline_with_foreign_route(
        _config(
            route_resolution_strict=True,
            fail_on_misconfiguration=False,
            ban_on_hostile_signals=True,
            auto_ban_threshold=2,
        )
    )

    for _ in range(6):
        response = send_request(pipeline, route_id, ip=FOREIGN_IP)
        assert response is not None
        assert response.status_code == 500

    assert not ipban_handler.ip_ban_manager.is_ip_banned(FOREIGN_IP)
