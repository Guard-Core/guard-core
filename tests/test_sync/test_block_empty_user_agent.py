from typing import Any

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.checks.factory import build_default_pipeline
from guard_core.sync.decorators import SecurityDecorator
from tests.test_sync.conftest import SyncMockGuardRequest
from tests.test_sync.test_core.conftest import build_middleware


def _outcome(
    headers: dict[str, str], **settings: Any
) -> tuple[int | None, list[dict[str, Any]]]:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        **settings,
    )
    middleware = build_middleware(config, SecurityDecorator(config))
    request = SyncMockGuardRequest(
        path="/x", client_host="203.0.113.5", headers=headers
    )
    response = build_default_pipeline(middleware).execute(request)
    events = [
        dict(call.kwargs)
        for call in middleware.event_bus.send_middleware_event.call_args_list
    ]
    return (None if response is None else response.status_code), events


def test_the_flag_defaults_to_off() -> None:
    assert SecurityConfig(enable_redis=False).block_empty_user_agent is False


def test_an_absent_user_agent_is_allowed_by_default() -> None:
    status, _ = _outcome({})

    assert status is None


def test_the_flag_blocks_an_absent_user_agent() -> None:
    status, events = _outcome({}, block_empty_user_agent=True)

    assert status == 403
    [event] = [e for e in events if e["event_type"] == "user_agent_blocked"]
    assert event["filter_type"] == "global"


@pytest.mark.parametrize("value", ["", "   "])
def test_the_flag_blocks_an_empty_or_blank_user_agent(value: str) -> None:
    status, _ = _outcome({"User-Agent": value}, block_empty_user_agent=True)

    assert status == 403


def test_the_flag_leaves_a_real_user_agent_alone() -> None:
    status, _ = _outcome({"User-Agent": "curl/8.4"}, block_empty_user_agent=True)

    assert status is None


def test_the_flag_works_together_with_a_blocked_user_agent_list() -> None:
    config = {"block_empty_user_agent": True, "blocked_user_agents": ["sqlmap"]}

    assert (_outcome({}, **config))[0] == 403
    assert (_outcome({"User-Agent": "sqlmap/1.7"}, **config))[0] == 403
    assert (_outcome({"User-Agent": "Mozilla/5.0"}, **config))[0] is None


def test_a_blocked_empty_user_agent_is_logged_only_in_passive_mode() -> None:
    status, events = _outcome({}, block_empty_user_agent=True, passive_mode=True)

    assert status is None
    [event] = [e for e in events if e["event_type"] == "user_agent_blocked"]
    assert event["action_taken"] == "logged_only"
