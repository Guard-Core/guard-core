from typing import Any

import pytest

from guard_core.core.checks.factory import build_default_pipeline
from guard_core.decorators import SecurityDecorator
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest
from tests.test_core.conftest import build_middleware


async def _outcome(
    headers: dict[str, str], **settings: object
) -> tuple[int | None, list[dict[str, Any]]]:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        **settings,
    )
    middleware = build_middleware(config, SecurityDecorator(config))
    request = MockGuardRequest(path="/x", client_host="203.0.113.5", headers=headers)
    response = await build_default_pipeline(middleware).execute(request)
    events = [
        dict(call.kwargs)
        for call in middleware.event_bus.send_middleware_event.call_args_list
    ]
    return (None if response is None else response.status_code), events


def test_the_flag_defaults_to_off() -> None:
    assert SecurityConfig(enable_redis=False).block_empty_user_agent is False


async def test_an_absent_user_agent_is_allowed_by_default() -> None:
    status, _ = await _outcome({})

    assert status is None


async def test_the_flag_blocks_an_absent_user_agent() -> None:
    status, events = await _outcome({}, block_empty_user_agent=True)

    assert status == 403
    [event] = [e for e in events if e["event_type"] == "user_agent_blocked"]
    assert event["filter_type"] == "global"


@pytest.mark.parametrize("value", ["", "   "])
async def test_the_flag_blocks_an_empty_or_blank_user_agent(value: str) -> None:
    status, _ = await _outcome({"User-Agent": value}, block_empty_user_agent=True)

    assert status == 403


async def test_the_flag_leaves_a_real_user_agent_alone() -> None:
    status, _ = await _outcome({"User-Agent": "curl/8.4"}, block_empty_user_agent=True)

    assert status is None


async def test_the_flag_works_together_with_a_blocked_user_agent_list() -> None:
    config = {"block_empty_user_agent": True, "blocked_user_agents": ["sqlmap"]}

    assert (await _outcome({}, **config))[0] == 403
    assert (await _outcome({"User-Agent": "sqlmap/1.7"}, **config))[0] == 403
    assert (await _outcome({"User-Agent": "Mozilla/5.0"}, **config))[0] is None


async def test_a_blocked_empty_user_agent_is_logged_only_in_passive_mode() -> None:
    status, events = await _outcome({}, block_empty_user_agent=True, passive_mode=True)

    assert status is None
    [event] = [e for e in events if e["event_type"] == "user_agent_blocked"]
    assert event["action_taken"] == "logged_only"


async def test_a_whitelisted_client_is_not_blocked_for_an_empty_user_agent() -> None:
    status, _ = await _outcome(
        {},
        block_empty_user_agent=True,
        whitelist=["203.0.113.5"],
        whitelist_access_only=False,
    )

    assert status is None


async def test_an_exempt_client_is_not_blocked_for_an_empty_user_agent() -> None:
    status, _ = await _outcome(
        {}, block_empty_user_agent=True, exempt_ips=["203.0.113.5"]
    )

    assert status is None


async def test_the_denial_counts_as_a_user_agent_strike() -> None:
    from guard_core.handlers.ipban_handler import ip_ban_manager

    ip_ban_manager.banned_ips.clear()
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        block_empty_user_agent=True,
        ban_on_hostile_signals=True,
        auto_ban_threshold=2,
    )
    middleware = build_middleware(config, SecurityDecorator(config))
    pipeline = build_default_pipeline(middleware)

    statuses = []
    for _ in range(3):
        response = await pipeline.execute(
            MockGuardRequest(path="/x", client_host="203.0.113.5")
        )
        statuses.append(None if response is None else response.status_code)

    assert statuses == [403, 403, 403]
    assert await ip_ban_manager.is_ip_banned("203.0.113.5") is True
