from typing import Any
from unittest.mock import MagicMock

from guard_core.models import SecurityConfig
from guard_core.sync.utils import extract_client_ip
from tests.test_sync.conftest import SyncMockGuardRequest

UNTRUSTED_PEER = "198.51.100.9"


def _config(**settings: Any) -> SecurityConfig:
    return SecurityConfig(enable_redis=False, trusted_proxies=["10.0.0.5"], **settings)


def _events_sent(config: SecurityConfig, requests: int = 3) -> list[Any]:
    agent = MagicMock()
    agent.send_event = MagicMock()
    for _ in range(requests):
        request = SyncMockGuardRequest(
            client_host=UNTRUSTED_PEER, headers={"X-Forwarded-For": "203.0.113.7"}
        )
        extract_client_ip(request, config, agent)
    return [call.args[0] for call in agent.send_event.call_args_list]


def test_the_spoof_event_is_sent_by_default() -> None:
    events = _events_sent(_config())

    assert [event.event_type for event in events] == ["suspicious_request"]
    assert events[0].action_taken == "spoofing_detected"


def test_a_muted_suspicious_request_type_silences_the_spoof_event() -> None:
    config = _config(muted_event_types=frozenset({"suspicious_request"}))

    assert _events_sent(config) == []


def test_disabling_agent_events_silences_the_spoof_event() -> None:
    assert _events_sent(_config(agent_enable_events=False)) == []


def test_muting_another_type_keeps_the_spoof_event() -> None:
    config = _config(muted_event_types=frozenset({"ip_blocked"}))

    assert len(_events_sent(config)) == 1
