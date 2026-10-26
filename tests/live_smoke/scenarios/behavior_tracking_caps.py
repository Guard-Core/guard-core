import httpx

from tests.live_smoke.driver import ScenarioContext, wait_until
from tests.live_smoke.registry import scenario

_PATH = "/basic/ip"
_PARAMS = {"q": "hello"}
_FIRST_CLIENT = {"X-Smoke-Client": "192.168.50.61"}
_SECOND_CLIENT = {"X-Smoke-Client": "192.168.50.62"}
_ABOVE_ANY_SMOKE_TRAFFIC = 1000

_BASE: dict[str, object] = {
    "auto_ban_threshold": 1000,
    "rate_limit": 1000,
    "excluded_detection_headers": ["x-real-ip", "x-forwarded-for"],
    "enable_redis": False,
}


def _two_global_rules(action: str, threshold: int) -> list[dict[str, object]]:
    """Two rules that differ only in window, so each one keeps its own bucket."""
    return [
        {
            "rule_type": "usage",
            "threshold": threshold,
            "window": window,
            "action": action,
        }
        for window in (60, 61)
    ]


def _one_global_rule(action: str, threshold: int) -> list[dict[str, object]]:
    return _two_global_rules(action, threshold)[:1]


def _eviction_line(kind: str, cap: int, field: str) -> str:
    return (
        f"Behavior tracking evicted an entry of kind {kind} (memory store) "
        f"because it holds {cap} entries; raise SecurityConfig.{field} "
    )


def _logged(ctx: ScenarioContext, mark: str, needle: str) -> bool:
    return any(needle in line for line in ctx.stack.logs.lines_since(mark))


def _assert_eviction_logged(
    ctx: ScenarioContext, mark: str, kind: str, cap: int, field: str
) -> None:
    needle = _eviction_line(kind, cap, field)
    assert wait_until(lambda: _logged(ctx, mark, needle), timeout=15.0), (
        f"{field}={cap} never produced the eviction warning for kind {kind}; "
        f"recent lines: {ctx.stack.logs.lines_since(mark)[-10:]}"
    )


def _assert_no_eviction_of_kind(ctx: ScenarioContext, mark: str, kind: str) -> None:
    assert not _logged(ctx, mark, f"an entry of kind {kind} ("), (
        f"a cap that was not lowered dropped an entry of kind {kind}"
    )


def _get(ctx: ScenarioContext, headers: dict[str, str] | None = None) -> httpx.Response:
    return ctx.client.get(_PATH, params=_PARAMS, headers=headers or {})


@scenario(
    covers={"behavior_max_tracked_endpoints"},
    config={
        **_BASE,
        "behavior_max_tracked_endpoints": 1,
        "global_behavior_rules": _two_global_rules("log", _ABOVE_ANY_SMOKE_TRAFFIC),
    },
)
def behavior_max_tracked_endpoints_evicts_the_least_recent_bucket(
    ctx: ScenarioContext,
) -> None:
    mark = ctx.stack.logs.mark()

    statuses = [_get(ctx).status_code for _ in range(3)]

    assert statuses == [200, 200, 200], (
        f"a log-only global usage rule must never block: {statuses}"
    )
    _assert_eviction_logged(ctx, mark, "endpoint", 1, "behavior_max_tracked_endpoints")
    _assert_no_eviction_of_kind(ctx, mark, "endpoint_client")


@scenario(
    covers={"behavior_max_tracked_clients_per_endpoint"},
    config={
        **_BASE,
        "behavior_max_tracked_clients_per_endpoint": 1,
        "global_behavior_rules": _one_global_rule("log", _ABOVE_ANY_SMOKE_TRAFFIC),
    },
)
def behavior_max_tracked_clients_per_endpoint_evicts_the_least_recent_client(
    ctx: ScenarioContext,
) -> None:
    mark = ctx.stack.logs.mark()

    first = _get(ctx, _FIRST_CLIENT)
    second = _get(ctx, _SECOND_CLIENT)

    assert (first.status_code, second.status_code) == (200, 200), (
        "a log-only global usage rule must never block: "
        f"{first.status_code}, {second.status_code}"
    )
    _assert_eviction_logged(
        ctx, mark, "endpoint_client", 1, "behavior_max_tracked_clients_per_endpoint"
    )
    _assert_no_eviction_of_kind(ctx, mark, "endpoint (")


@scenario(
    covers={"behavior_throttle_max_tracked_buckets"},
    config={
        **_BASE,
        "behavior_throttle_max_tracked_buckets": 1,
        "global_behavior_rules": _two_global_rules(
            "throttle", _ABOVE_ANY_SMOKE_TRAFFIC
        ),
    },
)
def behavior_throttle_max_tracked_buckets_evicts_the_least_recent_bucket(
    ctx: ScenarioContext,
) -> None:
    mark = ctx.stack.logs.mark()

    statuses = [_get(ctx).status_code for _ in range(3)]

    assert statuses == [200, 200, 200], (
        f"a throttle far below its threshold must admit every request: {statuses}"
    )
    _assert_eviction_logged(
        ctx, mark, "throttle_bucket", 1, "behavior_throttle_max_tracked_buckets"
    )
    _assert_no_eviction_of_kind(ctx, mark, "throttle_client")


@scenario(
    covers={"behavior_throttle_max_tracked_clients_per_bucket"},
    config={
        **_BASE,
        "behavior_throttle_max_tracked_clients_per_bucket": 1,
        "global_behavior_rules": _one_global_rule("throttle", _ABOVE_ANY_SMOKE_TRAFFIC),
    },
)
def behavior_throttle_max_tracked_clients_per_bucket_evicts_the_least_recent_client(
    ctx: ScenarioContext,
) -> None:
    mark = ctx.stack.logs.mark()

    first = _get(ctx, _FIRST_CLIENT)
    second = _get(ctx, _SECOND_CLIENT)

    assert (first.status_code, second.status_code) == (200, 200), (
        "a throttle far below its threshold must admit every request: "
        f"{first.status_code}, {second.status_code}"
    )
    _assert_eviction_logged(
        ctx,
        mark,
        "throttle_client",
        1,
        "behavior_throttle_max_tracked_clients_per_bucket",
    )
    _assert_no_eviction_of_kind(ctx, mark, "throttle_bucket")


_TRIP_THRESHOLD = 2


@scenario(
    covers={"behavior_throttle_max_trip_markers"},
    config={
        **_BASE,
        "behavior_throttle_max_trip_markers": 1,
        "global_behavior_rules": _two_global_rules("throttle", _TRIP_THRESHOLD),
    },
)
def behavior_throttle_max_trip_markers_drops_the_oldest_running_marker(
    ctx: ScenarioContext,
) -> None:
    mark = ctx.stack.logs.mark()

    for _ in range(_TRIP_THRESHOLD + 3):
        _get(ctx)

    _assert_eviction_logged(
        ctx, mark, "trip_marker", 1, "behavior_throttle_max_trip_markers"
    )
    assert _logged(ctx, mark, "Throttle threshold reached") or _logged(
        ctx, mark, "Would throttle IP"
    ), "the rules never tripped, so no trip marker was ever created"
    _assert_no_eviction_of_kind(ctx, mark, "throttle_bucket")
