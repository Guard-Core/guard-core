from types import SimpleNamespace
from typing import Any

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks import helpers as helpers_module
from guard_core.sync.core.checks.helpers import get_cached_detection_result
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.detection_result import DetectionResult


def _make_request() -> Any:
    return SimpleNamespace(state=SimpleNamespace())


def _bypass_fn(calls: list[int] | None = None) -> Any:
    def bypass(*_a: Any, **_kw: Any) -> bool:
        if calls is not None:
            calls.append(1)
        return True

    return bypass


def test_second_call_with_same_route_config_reuses_cached_result() -> None:
    request = _make_request()
    config = SyncSecurityConfig()
    calls: list[int] = []

    first = get_cached_detection_result(request, None, config, _bypass_fn(calls))
    second = get_cached_detection_result(request, None, config, _bypass_fn(calls))

    assert first is second
    assert len(calls) == 1


def test_different_route_config_bypasses_the_cache() -> None:
    request = _make_request()
    config = SyncSecurityConfig(enable_penetration_detection=False)

    route_a = RouteConfig()
    route_b = RouteConfig()

    first = get_cached_detection_result(request, route_a, config, _bypass_fn())
    second = get_cached_detection_result(request, route_b, config, _bypass_fn())

    assert first is not second
    assert isinstance(first, DetectionResult)
    assert isinstance(second, DetectionResult)


def test_cache_stores_live_object_references_not_raw_ids() -> None:
    request = _make_request()
    config = SyncSecurityConfig(enable_penetration_detection=False)
    route_config = RouteConfig()

    get_cached_detection_result(request, route_config, config, _bypass_fn())

    cached_request, cached_route_config, _ = request.state._guard_detection_result_cache
    assert cached_request is request
    assert cached_route_config is route_config
    assert not isinstance(cached_request, int)
    assert not isinstance(cached_route_config, int)


def test_different_requests_never_share_a_cached_result() -> None:
    config = SyncSecurityConfig(enable_penetration_detection=False)

    first_request = _make_request()
    second_request = _make_request()

    first = get_cached_detection_result(first_request, None, config, _bypass_fn())
    second = get_cached_detection_result(second_request, None, config, _bypass_fn())

    assert first is not second
    assert hasattr(first_request.state, "_guard_detection_result_cache")
    assert hasattr(second_request.state, "_guard_detection_result_cache")


def test_reused_request_state_object_does_not_share_a_stale_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SyncSecurityConfig(enable_penetration_detection=True)
    route_config = RouteConfig()
    shared_state = SimpleNamespace()
    call_count = 0

    def fake_detect_penetration_patterns(
        request: Any, route_config: Any, config: Any, should_bypass_check_fn: Any
    ) -> DetectionResult:
        nonlocal call_count
        call_count += 1
        return DetectionResult(
            is_threat=call_count == 1, trigger_info=f"call-{call_count}"
        )

    monkeypatch.setattr(
        helpers_module, "detect_penetration_patterns", fake_detect_penetration_patterns
    )

    request_1 = SimpleNamespace(state=shared_state)
    request_2 = SimpleNamespace(state=shared_state)

    first = get_cached_detection_result(request_1, route_config, config, _bypass_fn())
    second = get_cached_detection_result(request_2, route_config, config, _bypass_fn())

    assert call_count == 2
    assert first is not second
    assert first.trigger_info == "call-1"
    assert second.trigger_info == "call-2"
