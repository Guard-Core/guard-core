from typing import Any
from unittest.mock import AsyncMock, MagicMock

from guard_core.models import SecurityConfig
from guard_core.utils import extract_client_ip
from tests.conftest import MockGuardRequest

UNTRUSTED_PEER = "198.51.100.9"


def _config(**settings: object) -> SecurityConfig:
    return SecurityConfig(enable_redis=False, trusted_proxies=["10.0.0.5"], **settings)


async def _events_sent(config: SecurityConfig, requests: int = 3) -> list[Any]:
    agent = MagicMock()
    agent.send_event = AsyncMock()
    for _ in range(requests):
        request = MockGuardRequest(
            client_host=UNTRUSTED_PEER, headers={"X-Forwarded-For": "203.0.113.7"}
        )
        await extract_client_ip(request, config, agent)
    return [call.args[0] for call in agent.send_event.call_args_list]


async def test_the_spoof_event_is_sent_by_default() -> None:
    events = await _events_sent(_config())

    assert [event.event_type for event in events] == ["suspicious_request"]
    assert events[0].action_taken == "spoofing_detected"


async def test_a_muted_suspicious_request_type_silences_the_spoof_event() -> None:
    config = _config(muted_event_types=frozenset({"suspicious_request"}))

    assert await _events_sent(config) == []


async def test_disabling_agent_events_silences_the_spoof_event() -> None:
    assert await _events_sent(_config(agent_enable_events=False)) == []


async def test_muting_another_type_keeps_the_spoof_event() -> None:
    config = _config(muted_event_types=frozenset({"ip_blocked"}))

    assert len(await _events_sent(config)) == 1
