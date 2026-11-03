from collections.abc import Callable

import pytest

from guard_core.core.checks import helpers as helpers_module
from guard_core.core.checks.helpers import get_cached_detection_result
from guard_core.decorators.base import RouteConfig
from guard_core.detection_result import DetectionResult
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from tests.conftest import MockGuardRequest


def _make_request() -> MockGuardRequest:
    return MockGuardRequest()


def _bypass_fn(
    calls: list[int] | None = None,
) -> Callable[[str, RouteConfig | None], bool]:
    def bypass(_path: str, _route: RouteConfig | None) -> bool:
        if calls is not None:
            calls.append(1)
        return True

    return bypass


async def test_second_call_with_same_route_config_reuses_cached_result() -> None:
    request = _make_request()
    config = SecurityConfig()
    calls: list[int] = []

    first = await get_cached_detection_result(request, None, config, _bypass_fn(calls))
    second = await get_cached_detection_result(request, None, config, _bypass_fn(calls))

    assert first is second
    assert len(calls) == 1


async def test_different_route_config_bypasses_the_cache() -> None:
    request = _make_request()
    config = SecurityConfig(enable_penetration_detection=False)

    route_a = RouteConfig()
    route_b = RouteConfig()

    first = await get_cached_detection_result(request, route_a, config, _bypass_fn())
    second = await get_cached_detection_result(request, route_b, config, _bypass_fn())

    assert first is not second
    assert isinstance(first, DetectionResult)
    assert isinstance(second, DetectionResult)


async def test_cache_stores_live_object_references_not_raw_ids() -> None:
    request = _make_request()
    config = SecurityConfig(enable_penetration_detection=False)
    route_config = RouteConfig()

    await get_cached_detection_result(request, route_config, config, _bypass_fn())

    cached = request.state._guard_detection_result_cache
    assert isinstance(cached, tuple)
    cached_request, cached_route_config, _ = cached
    assert cached_request is request
    assert cached_route_config is route_config
    assert not isinstance(cached_request, int)
    assert not isinstance(cached_route_config, int)


async def test_different_requests_never_share_a_cached_result() -> None:
    config = SecurityConfig(enable_penetration_detection=False)

    first_request = _make_request()
    second_request = _make_request()

    first = await get_cached_detection_result(first_request, None, config, _bypass_fn())
    second = await get_cached_detection_result(
        second_request, None, config, _bypass_fn()
    )

    assert first is not second
    assert hasattr(first_request.state, "_guard_detection_result_cache")
    assert hasattr(second_request.state, "_guard_detection_result_cache")


async def test_reused_request_state_object_does_not_share_a_stale_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SecurityConfig(enable_penetration_detection=True)
    route_config = RouteConfig()
    call_count = 0

    async def fake_detect_penetration_patterns(
        request: GuardRequest,
        route_config: RouteConfig | None,
        config: SecurityConfig,
        should_bypass_check_fn: Callable[[str, RouteConfig | None], bool],
    ) -> DetectionResult:
        nonlocal call_count
        call_count += 1
        return DetectionResult(
            is_threat=call_count == 1, trigger_info=f"call-{call_count}"
        )

    monkeypatch.setattr(
        helpers_module, "detect_penetration_patterns", fake_detect_penetration_patterns
    )

    request_1 = _make_request()
    request_2 = _make_request()
    request_2._state = request_1._state

    first = await get_cached_detection_result(
        request_1, route_config, config, _bypass_fn()
    )
    second = await get_cached_detection_result(
        request_2, route_config, config, _bypass_fn()
    )

    assert call_count == 2
    assert first is not second
    assert first.trigger_info == "call-1"
    assert second.trigger_info == "call-2"
