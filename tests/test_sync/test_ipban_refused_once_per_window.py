import logging
import time
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.ipban_handler import IPBanManager
from tests.fake_agent import mock_agent

DURATION = 600


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


def _manager() -> IPBanManager:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.config = SyncSecurityConfig(
        enable_redis=False, trusted_proxies=("10.1.0.0/16",)
    )
    manager.agent_handler = Mock(send_event=MagicMock())
    return manager


def _refusal_logs(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if "Refused to ban" in r.getMessage()]


def _events(manager: IPBanManager) -> list[Any]:
    return [
        call.args[0]
        for call in mock_agent(manager.agent_handler).send_event.call_args_list
    ]


def test_a_refused_ban_is_logged_once_per_ip_per_ban_window(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager()
    caplog.set_level(logging.WARNING, logger="guard_core.sync.handlers.ipban")

    for _ in range(5):
        assert manager.ban_ip("127.0.0.1", DURATION, "rate_limit_exceeded") is False

    assert len(_refusal_logs(caplog)) == 1


def test_each_refused_ip_gets_its_own_log_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager()
    caplog.set_level(logging.WARNING, logger="guard_core.sync.handlers.ipban")

    for _ in range(3):
        manager.ban_ip("127.0.0.1", DURATION, "rate_limit_exceeded")
        manager.ban_ip("10.1.2.3", DURATION, "rate_limit_exceeded")

    assert len(_refusal_logs(caplog)) == 2


def test_the_refusal_is_logged_again_after_the_ban_window(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = _manager()
    caplog.set_level(logging.WARNING, logger="guard_core.sync.handlers.ipban")
    now = [1_000_000.0]
    monkeypatch.setattr(time, "time", lambda: now[0])

    manager.ban_ip("127.0.0.1", DURATION, "rate_limit_exceeded")
    now[0] += DURATION - 1
    manager.ban_ip("127.0.0.1", DURATION, "rate_limit_exceeded")
    assert len(_refusal_logs(caplog)) == 1

    now[0] += 2
    manager.ban_ip("127.0.0.1", DURATION, "rate_limit_exceeded")
    assert len(_refusal_logs(caplog)) == 2


def test_a_refused_ban_sends_one_ip_ban_refused_event_per_window() -> None:
    manager = _manager()

    for _ in range(4):
        manager.ban_ip("127.0.0.1", DURATION, "rate_limit_exceeded")

    refused = [e for e in _events(manager) if e.event_type == "ip_ban_refused"]
    assert len(refused) == 1
    event = refused[0]
    assert event.ip_address == "127.0.0.1"
    assert event.action_taken == "ban_refused"
    assert event.metadata["refusal"] == "loopback"
    assert event.metadata["duration"] == DURATION
    assert event.metadata["ban_reason"] == "rate_limit_exceeded"


def test_a_trusted_proxy_refusal_names_its_cause_in_the_event() -> None:
    manager = _manager()

    manager.ban_ip("10.1.2.3", DURATION, "threshold_exceeded")

    (event,) = _events(manager)
    assert event.metadata["refusal"] == "trusted_proxy"


def test_an_applied_ban_sends_no_refused_event() -> None:
    manager = _manager()

    assert manager.ban_ip("203.0.113.9", DURATION, "threshold_exceeded") is True

    assert [e.event_type for e in _events(manager)] == ["ip_banned"]


def test_the_event_type_is_part_of_the_vocabulary() -> None:
    from guard_core.sync.core.events.event_types import (
        EVENT_IP_BAN_REFUSED,
        EVENT_TYPE_VALUES,
    )

    assert EVENT_IP_BAN_REFUSED == "ip_ban_refused"
    assert EVENT_IP_BAN_REFUSED in EVENT_TYPE_VALUES


def test_the_refusal_record_stays_within_its_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from guard_core.sync.handlers import _ipban_bans

    manager = _manager()
    monkeypatch.setattr(_ipban_bans, "_MAX_TRACKED_REFUSED_BANS", 2)
    now = [1_000_000.0]
    monkeypatch.setattr(time, "time", lambda: now[0])

    manager.ban_ip("127.0.0.1", 10, "rate_limit_exceeded")
    manager.ban_ip("127.0.0.2", 600, "rate_limit_exceeded")
    now[0] += 11
    manager.ban_ip("127.0.0.3", 600, "rate_limit_exceeded")
    assert set(manager.refused_ban_reported_until) == {"127.0.0.2", "127.0.0.3"}

    manager.ban_ip("127.0.0.4", 600, "rate_limit_exceeded")
    assert set(manager.refused_ban_reported_until) == {"127.0.0.3", "127.0.0.4"}


def test_a_failing_agent_never_breaks_the_refusal(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager()
    manager.agent_handler = Mock(
        send_event=MagicMock(side_effect=RuntimeError("agent down"))
    )
    caplog.set_level(logging.ERROR, logger="guard_core.sync.handlers.ipban")

    assert manager.ban_ip("127.0.0.1", DURATION, "rate_limit_exceeded") is False

    assert any(
        "Failed to send ban refused event to agent: agent down" in r.getMessage()
        for r in caplog.records
    )
