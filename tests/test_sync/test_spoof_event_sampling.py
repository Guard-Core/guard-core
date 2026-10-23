import logging
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils import ip_extraction, sampling
from guard_core.sync.utils import extract_client_ip
from tests.test_sync.conftest import SyncMockGuardRequest

PUBLIC_PEER = "93.184.216.9"
OTHER_PUBLIC_PEER = "93.184.216.10"
PRIVATE_PEER = "192.168.1.9"
WINDOW = ip_extraction._UNTRUSTED_XFF_WINDOW_SECONDS


class Spoofer:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.now = 1000.0
        monkeypatch.setattr(
            sampling, "time", SimpleNamespace(monotonic=lambda: self.now)
        )
        self.config = SyncSecurityConfig(
            enable_redis=False, trusted_proxies=["10.0.0.5"]
        )
        self.agent = MagicMock()
        self.agent.send_event = MagicMock()

    def send(self, peer: str, requests: int = 1) -> None:
        for _ in range(requests):
            request = SyncMockGuardRequest(
                client_host=peer, headers={"X-Forwarded-For": "203.0.113.7"}
            )
            extract_client_ip(request, self.config, self.agent)

    def events(self) -> list[Any]:
        return [call.args[0] for call in self.agent.send_event.call_args_list]

    def suppressed(self) -> list[tuple[Any, Any]]:
        return [
            (e.metadata["suppressed_count"], e.metadata["suppressed_evicted_count"])
            for e in self.events()
        ]


def _spoof_records(caplog: pytest.LogCaptureFixture, level: int) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.levelno == level and "Potential IP spoof attempt" in r.getMessage()
    ]


@pytest.fixture
def spoofer(monkeypatch: pytest.MonkeyPatch) -> Spoofer:
    return Spoofer(monkeypatch)


def test_one_public_request_gives_one_warning_and_one_event(
    spoofer: Spoofer, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG):
        spoofer.send(PUBLIC_PEER)

    assert len(_spoof_records(caplog, logging.WARNING)) == 1
    assert spoofer.suppressed() == [(0, 0)]
    assert spoofer.events()[0].action_taken == "spoofing_detected"


def test_a_public_peer_is_sampled_once_per_window_with_a_count(
    spoofer: Spoofer, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG):
        spoofer.send(PUBLIC_PEER, 100)
        assert len(_spoof_records(caplog, logging.WARNING)) == 1
        assert spoofer.suppressed() == [(0, 0)]

        spoofer.now += WINDOW + 1
        spoofer.send(PUBLIC_PEER)

    assert spoofer.suppressed() == [(0, 0), (99, 0)]
    assert len(_spoof_records(caplog, logging.WARNING)) == 2


def test_a_private_peer_sends_one_event_per_window_and_logs_every_request(
    spoofer: Spoofer, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG):
        spoofer.send(PRIVATE_PEER, 100)
        assert len(_spoof_records(caplog, logging.DEBUG)) == 100
        assert spoofer.suppressed() == [(0, 0)]

        spoofer.now += WINDOW + 1
        spoofer.send(PRIVATE_PEER)

    assert spoofer.suppressed() == [(0, 0), (99, 0)]
    assert _spoof_records(caplog, logging.WARNING) == []


def test_two_peers_are_counted_separately(spoofer: Spoofer) -> None:
    spoofer.send(PUBLIC_PEER, 3)
    spoofer.send(OTHER_PUBLIC_PEER, 5)
    spoofer.now += WINDOW + 1
    spoofer.send(PUBLIC_PEER)
    spoofer.send(OTHER_PUBLIC_PEER)

    assert spoofer.suppressed() == [(0, 0), (0, 0), (2, 0), (4, 0)]


def test_an_evicted_peers_count_rides_the_next_event_sent(
    spoofer: Spoofer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ip_extraction, "_MAX_TRACKED_UNTRUSTED_PEERS", 2)
    spoofer.send(PUBLIC_PEER, 4)
    spoofer.send(OTHER_PUBLIC_PEER)
    spoofer.send("93.184.216.11")
    assert spoofer.suppressed() == [(0, 0), (0, 0), (0, 3)]

    spoofer.send("93.184.216.12")
    spoofer.now += WINDOW + 1
    spoofer.send(PUBLIC_PEER)

    assert spoofer.suppressed()[3:] == [(0, 0), (0, 0)]


def test_a_peer_evicted_with_a_pending_count_comes_back_at_zero(
    spoofer: Spoofer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ip_extraction, "_MAX_TRACKED_UNTRUSTED_PEERS", 1)
    spoofer.send(PUBLIC_PEER, 4)
    spoofer.send(OTHER_PUBLIC_PEER)
    spoofer.send(PUBLIC_PEER)

    assert spoofer.suppressed() == [(0, 0), (0, 3), (0, 0)]


def test_the_evicted_count_is_kept_while_the_event_is_muted(
    spoofer: Spoofer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ip_extraction, "_MAX_TRACKED_UNTRUSTED_PEERS", 1)
    spoofer.config.muted_event_types = frozenset({"suspicious_request"})
    spoofer.send(PUBLIC_PEER, 4)
    spoofer.send(OTHER_PUBLIC_PEER)
    spoofer.config.muted_event_types = frozenset()
    spoofer.now += WINDOW + 1
    spoofer.send(OTHER_PUBLIC_PEER)

    assert spoofer.suppressed() == [(0, 3)]


def test_a_muted_type_or_disabled_events_still_drop_the_sampled_event(
    spoofer: Spoofer,
) -> None:
    spoofer.config.muted_event_types = frozenset({"suspicious_request"})
    spoofer.send(PUBLIC_PEER)
    spoofer.config.muted_event_types = frozenset()
    spoofer.config.agent_enable_events = False
    spoofer.send(OTHER_PUBLIC_PEER)

    assert spoofer.events() == []
