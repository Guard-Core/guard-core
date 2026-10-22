import logging
from collections.abc import AsyncGenerator
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import ValidationError

from guard_core._utils import sampling
from guard_core.handlers._behavior_throttle import ThrottleCheck, usage_hits_key
from guard_core.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from tests.conftest import REDIS_PREFIX, REDIS_URL

CAP_FIELDS = (
    "behavior_max_tracked_endpoints",
    "behavior_max_tracked_clients_per_endpoint",
    "behavior_throttle_max_tracked_buckets",
    "behavior_throttle_max_tracked_clients_per_bucket",
    "behavior_throttle_max_trip_markers",
)
WINDOW = 60
NOW = 1_000_000.0


def _usage_rule(threshold: int = 999) -> BehaviorRule:
    return BehaviorRule(rule_type="usage", threshold=threshold, window=WINDOW)


def _throttle_rule(threshold: int = 1) -> BehaviorRule:
    return BehaviorRule(
        rule_type="usage", threshold=threshold, window=3600, action="throttle"
    )


def _tracker(**caps: int) -> tuple[BehaviorTracker, MagicMock]:
    config = SecurityConfig(enable_redis=False, **caps)
    tracker = BehaviorTracker(config)
    agent = MagicMock()
    agent.send_event = AsyncMock()
    tracker.agent_handler = agent
    return tracker, agent


def _events(agent: MagicMock) -> list[Any]:
    return [call.args[0] for call in agent.send_event.call_args_list]


def _kinds(agent: MagicMock) -> list[str]:
    return [e.metadata["kind"] for e in _events(agent)]


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.WARNING and "Behavior tracking" in r.getMessage()
    ]


async def _fill_endpoints(tracker: BehaviorTracker, count: int) -> None:
    for n in range(count):
        await tracker.track_endpoint_usage(f"/ep{n}", f"203.0.113.{n}", _usage_rule())


async def _fill_clients(tracker: BehaviorTracker, count: int) -> None:
    for n in range(count):
        await tracker.track_endpoint_usage("/ep", f"203.0.113.{n}", _usage_rule())


async def _fill_throttle_buckets(tracker: BehaviorTracker, count: int) -> None:
    for n in range(count):
        check = ThrottleCheck(_throttle_rule(), f"/ep{n}", True, 99)
        await tracker.check_throttle("203.0.113.1", [check], NOW, False)


async def _fill_throttle_clients(tracker: BehaviorTracker, count: int) -> None:
    for n in range(count):
        check = ThrottleCheck(_throttle_rule(), "/ep", True, 99)
        await tracker.check_throttle(f"203.0.113.{n}", [check], NOW, False)


async def _trip_clients(tracker: BehaviorTracker, count: int) -> list[Any]:
    trips: list[Any] = []
    for n in range(count):
        check = ThrottleCheck(_throttle_rule(), "/ep", True, 1)
        for step in range(2):
            trips = await tracker.check_throttle(
                f"203.0.113.{n}", [check], NOW + step, False
            )
    return trips


EVICTING_FILLS = {
    "endpoint": ("behavior_max_tracked_endpoints", _fill_endpoints),
    "endpoint_client": (
        "behavior_max_tracked_clients_per_endpoint",
        _fill_clients,
    ),
    "throttle_bucket": (
        "behavior_throttle_max_tracked_buckets",
        _fill_throttle_buckets,
    ),
    "throttle_client": (
        "behavior_throttle_max_tracked_clients_per_bucket",
        _fill_throttle_clients,
    ),
    "trip_marker": ("behavior_throttle_max_trip_markers", _trip_clients),
}


def test_the_five_caps_default_to_ten_thousand_and_reject_zero() -> None:
    config = SecurityConfig(enable_redis=False)

    assert [getattr(config, field) for field in CAP_FIELDS] == [10_000] * 5
    for field in CAP_FIELDS:
        with pytest.raises(ValidationError):
            SecurityConfig(enable_redis=False, **{field: 0})


def test_each_cap_description_names_its_own_effect() -> None:
    fields = SecurityConfig.model_fields

    described = {name: fields[name].description or "" for name in CAP_FIELDS}

    assert "restarts" in described["behavior_max_tracked_endpoints"]
    assert "recent-hits total" in described["behavior_max_tracked_endpoints"]
    assert "Redis" in described["behavior_max_tracked_endpoints"]
    assert "ban threshold can be missed" in described[CAP_FIELDS[1]]
    assert "admitted again" in described[CAP_FIELDS[2]]
    assert "admitted again" in described[CAP_FIELDS[3]]
    assert "stays throttled" in described[CAP_FIELDS[4]]


@pytest.mark.parametrize("kind", list(EVICTING_FILLS))
async def test_a_cap_of_two_filled_to_three_evicts_one_and_reports_it(
    kind: str, caplog: pytest.LogCaptureFixture
) -> None:
    field, fill = EVICTING_FILLS[kind]
    tracker, agent = _tracker(**{field: 2})

    with caplog.at_level(logging.WARNING):
        await fill(tracker, 3)

    events = _events(agent)
    assert [e.event_type for e in events] == ["behavior_bucket_evicted"]
    assert events[0].metadata == {
        "kind": kind,
        "cap": 2,
        "store": "memory",
        "outcome": "evicted",
        "suppressed_count": 0,
    }
    warnings = _warnings(caplog)
    assert len(warnings) == 1
    assert "203.0.113" not in warnings[0]
    assert field in warnings[0]


@pytest.mark.parametrize("kind", list(EVICTING_FILLS))
async def test_a_cap_that_is_not_reached_reports_nothing(
    kind: str, caplog: pytest.LogCaptureFixture
) -> None:
    field, fill = EVICTING_FILLS[kind]
    tracker, agent = _tracker(**{field: 3})

    with caplog.at_level(logging.WARNING):
        await fill(tracker, 3)

    assert _events(agent) == []
    assert _warnings(caplog) == []


async def test_a_burst_of_evictions_sends_one_event_per_window_with_a_count(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    clock = [1000.0]
    monkeypatch.setattr(sampling, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    tracker, agent = _tracker(behavior_max_tracked_endpoints=1)

    with caplog.at_level(logging.WARNING):
        await _fill_endpoints(tracker, 51)
        assert [e.metadata["suppressed_count"] for e in _events(agent)] == [0]
        assert len(_warnings(caplog)) == 1

        clock[0] += 61
        await tracker.track_endpoint_usage("/more", "203.0.113.200", _usage_rule())

    assert [e.metadata["suppressed_count"] for e in _events(agent)] == [0, 49]
    assert len(_warnings(caplog)) == 2


async def test_kinds_are_sampled_separately() -> None:
    tracker, agent = _tracker(
        behavior_max_tracked_endpoints=1, behavior_max_tracked_clients_per_endpoint=1
    )

    await _fill_endpoints(tracker, 3)
    await _fill_clients(tracker, 3)

    assert sorted(_kinds(agent)) == ["endpoint", "endpoint_client"]


@pytest.mark.parametrize("muted", [True, False])
async def test_the_gates_drop_the_event_and_keep_the_warning(
    muted: bool, caplog: pytest.LogCaptureFixture
) -> None:
    tracker, agent = _tracker(behavior_max_tracked_endpoints=1)
    if muted:
        tracker.config.muted_event_types = frozenset({"behavior_bucket_evicted"})
    else:
        tracker.config.agent_enable_events = False

    with caplog.at_level(logging.WARNING):
        await _fill_endpoints(tracker, 3)

    assert _events(agent) == []
    assert len(_warnings(caplog)) == 1


async def test_without_an_agent_the_warning_is_logged_and_nothing_is_queued(
    caplog: pytest.LogCaptureFixture,
) -> None:
    tracker, _ = _tracker(behavior_max_tracked_endpoints=1)
    tracker.agent_handler = None

    with caplog.at_level(logging.WARNING):
        await _fill_endpoints(tracker, 3)

    assert len(_warnings(caplog)) == 1
    assert tracker._evicted_values == []


async def test_an_evicted_client_with_no_hits_is_not_reported() -> None:
    tracker, agent = _tracker(behavior_max_tracked_clients_per_endpoint=1)
    rule = _usage_rule()

    for n in range(3):
        await tracker.track_endpoint_usage("/ep", f"203.0.113.{n}", rule, record=False)

    assert _events(agent) == []


async def test_an_evicted_client_restarts_its_count() -> None:
    tracker, agent = _tracker(behavior_max_tracked_clients_per_endpoint=2)
    rule = _usage_rule(threshold=2)
    first = "203.0.113.1"

    for _ in range(2):
        assert await tracker.track_endpoint_usage("/ep", first, rule) is False
    await tracker.track_endpoint_usage("/ep", "203.0.113.2", rule)
    await tracker.track_endpoint_usage("/ep", "203.0.113.3", rule)

    assert await tracker.track_endpoint_usage("/ep", first, rule) is False
    assert _kinds(agent)[0] == "endpoint_client"


async def test_an_evicted_trip_marker_leaves_the_client_throttled() -> None:
    tracker, agent = _tracker(behavior_throttle_max_trip_markers=2)
    check = ThrottleCheck(_throttle_rule(), "/ep", True, 1)
    first = "203.0.113.0"

    await _trip_clients(tracker, 3)
    again = await tracker.check_throttle(first, [check], NOW + 2, False)

    assert [t.first_of_episode for t in again] == [True]
    assert _kinds(agent)[0] == "trip_marker"


async def test_an_expired_trip_marker_is_not_reported() -> None:
    tracker, agent = _tracker(behavior_throttle_max_trip_markers=1)
    check = ThrottleCheck(_throttle_rule(), "/ep", True, 1)

    for n, now in enumerate((NOW, NOW + 10_000)):
        for step in range(2):
            await tracker.check_throttle(f"203.0.113.{n}", [check], now + step, False)

    assert _events(agent) == []


def _handler(tracker: BehaviorTracker) -> RedisManager:
    assert isinstance(tracker.redis_handler, RedisManager)
    return tracker.redis_handler


@pytest.fixture
async def redis_tracker() -> AsyncGenerator[tuple[BehaviorTracker, MagicMock], None]:
    config = SecurityConfig(
        redis_url=REDIS_URL,
        redis_prefix=REDIS_PREFIX,
        behavior_max_tracked_endpoints=2,
    )
    handler = RedisManager(config)
    await handler.initialize()
    tracker = BehaviorTracker(config)
    await tracker.initialize_redis(handler)
    agent = MagicMock()
    agent.send_event = AsyncMock()
    tracker.agent_handler = agent
    yield tracker, agent
    await handler.close()


async def test_a_full_rule_hit_index_refuses_one_key_and_still_counts_the_hit(
    redis_tracker: tuple[BehaviorTracker, MagicMock],
) -> None:
    tracker, agent = redis_tracker
    client = "203.0.113.77"
    rule = _usage_rule()
    for n in range(2):
        await tracker.track_endpoint_usage(f"/index{n}", client, rule)
    assert _events(agent) == []

    await tracker.track_endpoint_usage("/refused", client, rule)
    await tracker.track_endpoint_usage("/refused", client, rule)

    events = _events(agent)
    assert len(events) == 1
    assert events[0].metadata == {
        "kind": "rule_hit_index",
        "cap": 2,
        "store": "redis",
        "outcome": "refused",
        "suppressed_count": 0,
    }
    assert events[0].action_taken == "refused"
    own_count = await _handler(tracker).count_sliding_window_hits(
        "behavior_usage",
        usage_hits_key("/refused", client, rule),
        0.0,
    )
    assert own_count == 2
    assert await tracker.count_recent_rule_hits(client, 300) == 2


async def test_a_full_rule_hit_index_is_reported_by_the_throttle_script(
    redis_tracker: tuple[BehaviorTracker, MagicMock],
) -> None:
    tracker, agent = redis_tracker
    client = "203.0.113.78"
    for n in range(2):
        await tracker.track_endpoint_usage(f"/index{n}", client, _usage_rule())
    check = ThrottleCheck(_throttle_rule(), "/throttled", True, 99)

    trips = await tracker.check_throttle(client, [check], NOW, False)

    assert trips == []
    assert _kinds(agent) == ["rule_hit_index"]
    assert _events(agent)[0].metadata["store"] == "redis"


async def test_the_sliding_window_return_contract_is_unchanged_without_the_flag(
    redis_tracker: tuple[BehaviorTracker, MagicMock],
) -> None:
    tracker, _ = redis_tracker
    handler = _handler(tracker)
    for n in range(2):
        await handler.record_sliding_window_hit(
            "behavior_usage", f"k{n}", NOW, NOW - 60, 60, index=("idx", 2)
        )

    refused: list[bool] = []
    plain = await handler.record_sliding_window_hit(
        "behavior_usage", "k2", NOW, NOW - 60, 60, index=("idx", 2)
    )
    flagged = await handler.record_sliding_window_hit(
        "behavior_usage",
        "k3",
        NOW,
        NOW - 60,
        60,
        index=("idx", 2),
        index_refused=refused,
    )

    assert plain == 1
    assert type(plain) is int
    assert flagged == 1
    assert refused == [True]
