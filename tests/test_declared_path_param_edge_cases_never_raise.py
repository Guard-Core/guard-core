import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core._utils.route_gate import isolate_declared_path_params, route_knowledge
from guard_core.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest, declare_route


def _check(config: SecurityConfig) -> SuspiciousActivityCheck:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("test_config_time_misconfigurations")
    middleware.suspicious_request_counts = {}
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.route_resolver.should_bypass_check = lambda *_: False
    return SuspiciousActivityCheck(middleware)


def _request(
    path: str, template: str, path_params: set[str], route_id: str = "app.item"
) -> MockGuardRequest:
    request = MockGuardRequest(path=path)
    declare_route(request, template)
    request.state.client_ip = "203.0.113.41"
    request.state.guard_route_id = route_id
    route_config = RouteConfig()
    route_config.excluded_detection_path_params = path_params
    request.state.route_config = route_config
    return request


@pytest.mark.parametrize("flag", [True, False])
async def test_a_root_capture_never_raises_per_request(
    flag: bool, caplog: pytest.LogCaptureFixture
) -> None:
    check = _check(SecurityConfig(enable_redis=False, fail_on_misconfiguration=flag))
    request = _request("/item", "/{item_id}", {"item_id"})

    with caplog.at_level(logging.WARNING):
        await check.check(request)
        await check.check(request)

    assert len([r for r in caplog.records if "item_id" in r.getMessage()]) == 1


@pytest.mark.parametrize("template", ["/{item_id}", "/{item_id:path}", "/<item_id>"])
def test_a_root_capture_leaves_the_whole_path_to_the_scan(template: str) -> None:
    with route_knowledge(
        template, declared_path_params={"item_id": frozenset({"recon"})}
    ):
        assert isolate_declared_path_params("/language", "recon") is None


def test_a_name_after_a_literal_segment_is_still_isolated() -> None:
    declared = {"item_id": frozenset({"recon"})}
    with route_knowledge("/items/{item_id}", declared_path_params=declared):
        assert isolate_declared_path_params("/items/language", "recon") is not None


@pytest.mark.parametrize("flag", [True, False])
async def test_a_name_the_template_lacks_warns_once_per_template_and_name(
    flag: bool, caplog: pytest.LogCaptureFixture
) -> None:
    check = _check(SecurityConfig(enable_redis=False, fail_on_misconfiguration=flag))
    request = _request("/items/1", "/items/{id}", {"ghost"})
    other = _request("/things/1", "/things/{id}", {"ghost"}, route_id="app.thing")

    with caplog.at_level(logging.WARNING):
        for _ in range(3):
            await check.check(request)
        await check.check(other)

    reports = [r.getMessage() for r in caplog.records if "'ghost'" in r.getMessage()]
    assert len(reports) == 2
    assert "'/items/{id}'" in reports[0]
    assert "'/things/{id}'" in reports[1]


def _blocking_check(flag: bool) -> SuspiciousActivityCheck:
    check = _check(SecurityConfig(enable_redis=False, fail_on_misconfiguration=flag))
    check.middleware.__dict__["create_error_response"] = AsyncMock(
        side_effect=lambda status_code, default_message: SimpleNamespace(
            status_code=status_code, message=default_message
        )
    )
    return check


@pytest.mark.parametrize("flag", [True, False])
@pytest.mark.parametrize("path", ["/wp-admin", "/language"])
async def test_a_probe_on_a_root_capture_route_is_still_blocked(
    flag: bool, path: str
) -> None:
    request = _request(path, "/{item_id}", {"item_id"})

    response = await _blocking_check(flag).check(request)

    assert response is not None
    assert response.status_code == 400


@pytest.mark.parametrize("flag", [True, False])
async def test_the_same_probe_after_a_literal_segment_is_still_exempted(
    flag: bool,
) -> None:
    # a declared value is still scanned by the value rules (wp-admin matches there),
    # so the control is a recon token only the path rows flag
    request = _request("/items/language", "/items/{item_id}", {"item_id"})

    assert await _blocking_check(flag).check(request) is None
