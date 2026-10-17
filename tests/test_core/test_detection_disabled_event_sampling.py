import time
from typing import Any

import pytest

from guard_core._utils import sampling
from guard_core.models import SecurityConfig
from tests.test_core.conftest import build_route_pipeline, send_request

WINDOW = 60


def _config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=True,
        enable_rate_limiting=False,
        enable_ip_banning=False,
    )


def _build() -> tuple[Any, Any, str]:
    return build_route_pipeline(_config(), lambda d: d.suspicious_detection(False))


def _disabled_events(middleware: Any) -> list[Any]:
    return [
        call
        for call in middleware.event_bus.send_middleware_event.call_args_list
        if call.kwargs.get("action_taken") == "detection_disabled"
    ]


async def test_one_client_sending_many_requests_emits_one_event() -> None:
    pipeline, middleware, route_id = _build()

    for _ in range(25):
        await send_request(pipeline, route_id, ip="203.0.113.110")

    assert len(_disabled_events(middleware)) == 1


async def test_a_different_client_gets_its_own_event() -> None:
    pipeline, middleware, route_id = _build()

    await send_request(pipeline, route_id, ip="203.0.113.111")
    await send_request(pipeline, route_id, ip="203.0.113.112")
    await send_request(pipeline, route_id, ip="203.0.113.111")

    assert len(_disabled_events(middleware)) == 2


async def test_the_same_client_is_reported_again_after_the_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipeline, middleware, route_id = _build()
    now = time.monotonic()

    monkeypatch.setattr(sampling.time, "monotonic", lambda: now)
    await send_request(pipeline, route_id, ip="203.0.113.113")
    monkeypatch.setattr(sampling.time, "monotonic", lambda: now + WINDOW + 1)
    await send_request(pipeline, route_id, ip="203.0.113.113")

    assert len(_disabled_events(middleware)) == 2


async def test_the_sampled_table_stays_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipeline, middleware, route_id = _build()
    monkeypatch.setattr(
        "guard_core.core.checks.implementations.suspicious_activity."
        "_MAX_TRACKED_DISABLED_DETECTION_CLIENTS",
        2,
    )

    for n in range(5):
        await send_request(pipeline, route_id, ip=f"203.0.113.{120 + n}")

    assert len(_disabled_events(middleware)) == 5


async def test_the_event_carries_the_decorator_violation_details() -> None:
    pipeline, middleware, route_id = _build()

    await send_request(pipeline, route_id, ip="203.0.113.130")

    (call,) = _disabled_events(middleware)
    assert call.kwargs["event_type"] == "decorator_violation"
    assert call.kwargs["reason"] == (
        "Suspicious pattern detection disabled by route decorator"
    )
    assert call.kwargs["decorator_type"] == "advanced"
    assert call.kwargs["violation_type"] == "suspicious_detection_disabled"


async def test_two_routes_get_separate_events_for_the_same_client() -> None:
    pipeline, middleware, first_route = _build()

    def second() -> None:
        pass

    second.__module__ = "pipeline_harness_second"
    second_route = middleware.guard_decorator.suspicious_detection(False)(
        second
    )._guard_route_id

    await send_request(pipeline, first_route, ip="203.0.113.131")
    await send_request(pipeline, second_route, ip="203.0.113.131")
    await send_request(pipeline, first_route, ip="203.0.113.131")

    assert len(_disabled_events(middleware)) == 2


def test_the_sampler_follows_the_window_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import threading
    from collections import OrderedDict

    table: OrderedDict[str, float] = OrderedDict()
    lock = threading.Lock()
    clock = {"now": 1000.0}
    monkeypatch.setattr(sampling.time, "monotonic", lambda: clock["now"])

    def observe(key: str = "k", max_tracked: int = 2) -> bool:
        return sampling.observe_sampled_key(
            table, lock, key, window=WINDOW, max_tracked=max_tracked
        )

    assert observe() is True
    clock["now"] = 1030.0
    assert observe() is False
    clock["now"] = 1059.9
    assert observe() is False
    clock["now"] = 1060.0
    assert observe() is True

    observe("a")
    observe("b")
    assert list(table) == ["a", "b"]


async def test_the_event_window_is_sixty_seconds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipeline, middleware, route_id = _build()
    now = time.monotonic()

    monkeypatch.setattr(sampling.time, "monotonic", lambda: now)
    await send_request(pipeline, route_id, ip="203.0.113.132")
    monkeypatch.setattr(sampling.time, "monotonic", lambda: now + 59.5)
    await send_request(pipeline, route_id, ip="203.0.113.132")
    assert len(_disabled_events(middleware)) == 1

    monkeypatch.setattr(sampling.time, "monotonic", lambda: now + 60.0)
    await send_request(pipeline, route_id, ip="203.0.113.132")
    assert len(_disabled_events(middleware)) == 2
