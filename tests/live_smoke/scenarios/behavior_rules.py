import json
import time
from collections.abc import Callable
from typing import Any

import httpx

from tests.live_smoke.driver import ScenarioContext, run_in_app_container, wait_until
from tests.live_smoke.registry import scenario

_BASE = {
    "auto_ban_threshold": 1000,
    "rate_limit": 1000,
    "excluded_detection_headers": ["x-real-ip", "x-forwarded-for"],
}


def _lines_mentioning(ctx: ScenarioContext, mark: str, needle: str) -> list[str]:
    return [line for line in ctx.stack.logs.lines_since(mark) if needle in line]


_THROTTLE_AGENT: dict[str, Any] = {
    "enable_agent": True,
    "agent_api_key": "smoke-agent-key",
    "agent_endpoint": "http://agent-stub:8090",
    "agent_flush_interval": 2,
}
_ADAPTER_ANSWERS_THROTTLE_PROBE = (
    "import guard.middleware as middleware\n"
    "print(hasattr(middleware.SecurityMiddleware, '_apply_usage_rules'))"
)


def _adapter_answers_throttle(ctx: ScenarioContext) -> bool:
    """Whether the installed adapter answers the engine's throttle 429 (D-30).

    fastapi-guard d92eb0c added `_apply_usage_rules`, the adapter side of the
    engine's throttle. The installed adapter decides, never the status a request
    got, so neither branch of a scenario can pass for the wrong reason. The
    version cannot decide: the 8.1.2 release and a build from the head both
    report 8.1.2.
    """
    result = run_in_app_container(_ADAPTER_ANSWERS_THROTTLE_PROBE)
    assert result.returncode == 0, result.stderr
    answer = result.stdout.strip()
    assert answer in {"True", "False"}, f"unexpected adapter probe output: {answer!r}"
    return answer == "True"


def _throttle_trip_events(ctx: ScenarioContext, details: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = ctx.agent.get("/_debug/state").json()["events"]
    return [
        event
        for event in events
        if event.get("event_type") == "behavioral_violation"
        and str(event.get("reason", "")).endswith(details)
    ]


def _settled_trip_events(ctx: ScenarioContext, details: str) -> list[dict[str, Any]]:
    """The trip events once the first has arrived and another flush has passed."""
    wait_until(lambda: _throttle_trip_events(ctx, details), timeout=20.0)
    time.sleep(_THROTTLE_AGENT["agent_flush_interval"] + 1)
    return _throttle_trip_events(ctx, details)


def _assert_throttle_only_logged(
    ctx: ScenarioContext, mark: str, details: str, statuses: list[int]
) -> None:
    assert statuses == [200] * len(statuses), (
        "an adapter that does not answer the engine's throttle must not block: "
        f"{statuses}"
    )
    assert _lines_mentioning(ctx, mark, "Would throttle IP") and _lines_mentioning(
        ctx, mark, f"Throttle threshold reached: {details}"
    ), "the observe-only throttle line was never logged"
    # one-time warning per process; each scenario's config restarts the app
    assert (
        "Behavior throttle rules are only logged" in ctx.stack.logs.current_boot_text()
    ), "the one-time observe-only throttle warning was never logged"
    events = _settled_trip_events(ctx, details)
    assert [event.get("action_taken") for event in events] == ["logged_only"], events


def _assert_throttle_enforced(
    ctx: ScenarioContext,
    mark: str,
    details: str,
    threshold: int,
    window: int,
    send: Callable[[], httpx.Response],
) -> None:
    admitted = [send().status_code for _ in range(threshold)]
    assert admitted == [200] * threshold, (
        f"the first {threshold} requests are within the threshold and must be "
        f"admitted: {admitted}"
    )
    refused = [send() for _ in range(4)]
    assert [response.status_code for response in refused] == [429] * 4, (
        "the request over the threshold and the ones after it must get 429: "
        f"{[response.status_code for response in refused]}"
    )
    for response in refused:
        retry_after = response.headers.get("Retry-After", "")
        assert retry_after.isdigit() and 1 <= int(retry_after) <= window, (
            f"Retry-After must be a whole number of seconds within 1 to {window}: "
            f"{retry_after!r}"
        )
    assert _lines_mentioning(ctx, mark, "Throttling IP") and _lines_mentioning(
        ctx, mark, f"Throttle threshold reached: {details}"
    ), "the enforced throttle line was never logged"
    assert not _lines_mentioning(ctx, mark, "Would throttle IP"), (
        "an enforcing adapter logged the observe-only line"
    )
    assert (
        "Behavior throttle rules are only logged"
        not in ctx.stack.logs.current_boot_text()
    ), "an enforcing adapter logged the observe-only warning"
    events = _settled_trip_events(ctx, details)
    assert [event.get("action_taken") for event in events] == ["throttle"], (
        f"the trip event is sent once, on the first refusal of the episode: {events}"
    )


def _unique_config(rate_limit: int) -> dict[str, object]:
    return {**_BASE, "rate_limit": rate_limit}


def _throttle_config(rate_limit: int) -> dict[str, object]:
    return {**_unique_config(rate_limit), **_THROTTLE_AGENT}


@scenario(covers={"usage_monitor"}, config=_unique_config(1101))
def usage_monitor_logs_without_blocking(ctx: ScenarioContext) -> None:
    mark = ctx.stack.logs.mark()

    for _ in range(11):
        response = ctx.client.get("/behavior/usage-monitor")
        assert response.status_code == 200, (
            f"usage_monitor(action='log') blocked a request: {response.status_code}"
        )

    assert _lines_mentioning(
        ctx, mark, "Behavioral anomaly detected: Usage threshold exceeded: 10 calls"
    ), "usage_monitor never logged the threshold-exceeded warning"


@scenario(covers={"suspicious_frequency"}, config=_throttle_config(1102))
def suspicious_frequency_throttle_follows_the_adapter(ctx: ScenarioContext) -> None:
    enforcing = _adapter_answers_throttle(ctx)
    ctx.agent.post("/_debug/reset")
    mark = ctx.stack.logs.mark()

    def send() -> httpx.Response:
        return ctx.client.get("/behavior/suspicious-frequency")

    details = "5 calls in 10s"
    if enforcing:
        _assert_throttle_enforced(ctx, mark, details, 5, 10, send)
    else:
        statuses = [send().status_code for _ in range(10)]
        _assert_throttle_only_logged(ctx, mark, details, statuses)


@scenario(covers={"honeypot_detection"}, config=_unique_config(1103))
def honeypot_detection_blocks_bot_filled_field(ctx: ScenarioContext) -> None:
    clean = ctx.client.post("/advanced/honeypot", json={"input": "hello"})
    assert clean.status_code == 200, (
        f"honeypot_detection blocked a clean submission: {clean.status_code}"
    )

    filled = ctx.client.post(
        "/advanced/honeypot",
        json={"input": "hello", "honeypot_field": "bot-filled-this"},
    )
    assert filled.status_code == 403, (
        f"honeypot_detection did not block a filled honeypot field: "
        f"{filled.status_code}"
    )


@scenario(covers={"return_monitor"}, config=_unique_config(1104))
def return_monitor_decorator_allows_non_matching_status(
    ctx: ScenarioContext,
) -> None:
    for _ in range(4):
        response = ctx.client.get("/behavior/return-monitor/200")
        assert response.status_code == 200, (
            "return_monitor(pattern='status:404') interfered with a "
            f"non-matching status: {response.status_code}"
        )


@scenario(covers={"behavior_analysis"}, config=_throttle_config(1105))
def behavior_analysis_frequency_rule_follows_the_adapter(ctx: ScenarioContext) -> None:
    enforcing = _adapter_answers_throttle(ctx)
    ctx.agent.post("/_debug/reset")
    mark = ctx.stack.logs.mark()

    def send() -> httpx.Response:
        return ctx.client.post("/behavior/behavior-rules")

    details = "10 calls in 60s"
    if enforcing:
        _assert_throttle_enforced(ctx, mark, details, 10, 60, send)
    else:
        statuses = [send().status_code for _ in range(11)]
        _assert_throttle_only_logged(ctx, mark, details, statuses)


_GLOBAL_RULE_CONFIG = {
    **_BASE,
    "behavior_scan_response_body": True,
    "behavior_max_response_body_inspect_bytes": 65536,
    "global_behavior_rules": [
        {
            "rule_type": "return_pattern",
            "threshold": 3,
            "window": 60,
            "pattern": "json:message==Echo response",
            "action": "ban",
            "ban_duration": 30,
        }
    ],
}


def _echo_status(ctx: ScenarioContext) -> int:
    return ctx.client.post("/basic/echo", json={"note": "hello"}).status_code


def _banned(ctx: ScenarioContext) -> bool:
    return _echo_status(ctx) == 403


@scenario(
    covers={
        "global_behavior_rules",
        "behavior_scan_response_body",
        "behavior_max_response_body_inspect_bytes",
    },
    config=_GLOBAL_RULE_CONFIG,
)
def global_behavior_rules_bans_after_response_body_pattern_match(
    ctx: ScenarioContext,
) -> None:
    mark = ctx.stack.logs.mark()

    for _ in range(4):
        _echo_status(ctx)

    banned = wait_until(lambda: _banned(ctx), timeout=10.0)
    assert banned, "global_behavior_rules never banned the client after 4 matches"

    matched = _lines_mentioning(
        ctx,
        mark,
        "Global return pattern threshold exceeded: 3 for 'json:message==Echo response'",
    )
    assert matched, (
        "no log line recorded the global return_pattern rule match; "
        f"recent lines: {json.dumps(ctx.stack.logs.lines_since(mark)[-10:])}"
    )


_RECIDIVE_CONFIG = {
    **_GLOBAL_RULE_CONFIG,
    "enable_recidive": True,
    "recidive_factor": 2.0,
    "recidive_window": 3600,
    "recidive_max_duration": 600,
}


def _still_banned_after(ctx: ScenarioContext, seconds: float) -> bool:
    return not wait_until(lambda: _echo_status(ctx) != 403, timeout=seconds)


@scenario(
    covers={
        "enable_recidive",
        "recidive_factor",
        "recidive_window",
        "recidive_max_duration",
    },
    config=_RECIDIVE_CONFIG,
)
def recidive_doubles_a_repeat_behavioral_ban(ctx: ScenarioContext) -> None:
    for _ in range(4):
        _echo_status(ctx)
    assert wait_until(lambda: _banned(ctx), timeout=10.0), "no first ban"
    assert wait_until(lambda: _echo_status(ctx) != 403, timeout=45.0, interval=1.0), (
        "the 30 s ban never expired"
    )

    for _ in range(2):
        _echo_status(ctx)
    assert wait_until(lambda: _banned(ctx), timeout=10.0), "no second ban"

    assert _still_banned_after(ctx, 40.0), "the repeat ban lasted no longer than 30 s"
