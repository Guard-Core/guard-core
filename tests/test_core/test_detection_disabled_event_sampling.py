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
