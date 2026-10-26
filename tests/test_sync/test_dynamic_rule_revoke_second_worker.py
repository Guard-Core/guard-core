import json
import os
import subprocess
import sys
import time
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from guard_core.sync.handlers.redis_handler import RedisManager
from tests.test_sync.test_dynamic_rule_revoke_owned_only import (
    INSIDE_NETWORK,
    IP,
    NETWORK,
    OTHER,
    VERSION,
    Fleet,
    _close_fleet,
    _open_fleet,
)

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
ATTACKER = "2001:db8:1::99"
RULE_V6 = "2001:db8:1::1"
IDENTITY = "2001:db8:1::/64"
STRIKE_WINDOW = 3600
WORKER = """
import json, sys, time
from datetime import datetime, timezone
from unittest.mock import MagicMock

from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from guard_core.sync.handlers.redis_handler import RedisManager
from guard_core.models import DynamicRules, SecurityConfig, SyncSecurityConfig

def main(url, prefix):
    config = SyncSecurityConfig(
        redis_url=url, redis_prefix=prefix, enable_redis=True, enable_agent=True,
        agent_api_key="k", enable_dynamic_rules=True, enable_recidive=True,
    )
    redis_handler = RedisManager(config)
    redis_handler.initialize()
    ip_ban_manager.config = config
    ip_ban_manager.redis_handler = redis_handler
    ip_ban_manager._VERSION_RECHECK_SECONDS = 0.0
    DynamicRuleManager._instance = None
    manager = DynamicRuleManager(config)
    manager.redis_handler = redis_handler
    agent = MagicMock()
    agent.send_event = MagicMock()
    agent.get_dynamic_rules = MagicMock()
    manager.agent_handler = agent
    ip_ban_manager.agent_handler = agent
    print("ready", flush=True)
    for line in sys.stdin:
        command, *args = line.split()
        if command == "ask":
            reply = {ip: ip_ban_manager.is_ip_banned(ip) for ip in args}
        else:
            version, start, *ips = args
            agent.get_dynamic_rules.return_value = DynamicRules(
                rule_id="R", version=int(version), timestamp=datetime.now(timezone.utc),
                ip_blacklist=ips, ip_ban_duration=3600,
            )
            while time.time() < float(start):
                time.sleep(0.0005)
            manager.update_rules()
            sent = [call.args[0] for call in agent.send_event.call_args_list]
            reply = {"unban_events": sum(e.action_taken == "unbanned" for e in sent)}
        print(json.dumps(reply), flush=True)
    redis_handler.close()

main(sys.argv[1], sys.argv[2])
"""


class SecondWorker:
    """A warm worker process on the same Redis: it keeps its own caches between
    the questions, like a second worker of the same app."""

    def __init__(self, prefix: str) -> None:
        self.process = subprocess.Popen(
            [sys.executable, "-c", WORKER, REDIS_URL, prefix],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        assert self._stdout().readline().strip() == "ready"

    def _stdout(self) -> Any:
        assert self.process.stdout is not None
        return self.process.stdout

    def start(self, line: str) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(f"{line}\n")
        self.process.stdin.flush()

    def answer(self) -> dict[str, Any]:
        reply: dict[str, Any] = json.loads(self._stdout().readline())
        return reply

    def ask(self, *ips: str) -> dict[str, bool]:
        self.start(f"ask {' '.join(ips)}")
        return self.answer()

    def apply(self, version: int, ips: list[str], start: float = 0.0) -> dict[str, Any]:
        self.start(f"apply {version} {start} {' '.join(ips)}")
        return self.answer()

    def close(self) -> None:
        assert self.process.stdin is not None
        self.process.stdin.close()
        self.process.wait(timeout=60)
        self._stdout().close()


@pytest.fixture
def redis_fleet() -> Generator[Fleet, None]:
    opened = _open_fleet(True)
    assert opened.redis is not None
    config = ip_ban_manager.config
    assert config is not None
    config.enable_recidive = True
    yield opened
    _close_fleet(opened)


@pytest.fixture
def second_worker(redis_fleet: Fleet) -> Any:
    assert redis_fleet.redis is not None
    worker = SecondWorker(redis_fleet.redis.config.redis_prefix)
    yield worker
    worker.close()


def _identity_state(redis: RedisManager, identity: str) -> dict[str, Any]:
    prefix = redis.config.redis_prefix
    with redis.get_connection() as conn:
        keys = sorted([key[len(prefix) :] for key in conn.scan_iter(f"{prefix}*")])
        ttl = conn.ttl(f"{prefix}banned_identities:{identity}")
    return {
        "identity_ttl": ttl,
        "strike_keys": [key for key in keys if key.startswith("detection:strikes")],
        "strike_categories": redis.read_detection_categories(
            identity, time.time() - STRIKE_WINDOW
        ),
        "recidive": [key for key in keys if key.startswith("recidive:")],
    }


def _assert_state_kept(before: dict[str, Any], after: dict[str, Any]) -> None:
    assert before["identity_ttl"] > 0
    assert abs(after["identity_ttl"] - before["identity_ttl"]) <= 3
    assert after["strike_keys"] == before["strike_keys"] != []
    assert after["strike_categories"] == before["strike_categories"] == ["sqli"]
    assert after["recidive"] == before["recidive"] != []


def _strike_and_ban_identity(redis: RedisManager, identity: str) -> None:
    now = time.time()
    for _ in range(3):
        redis.record_detection_strikes(
            identity, ["sqli"], now, now - STRIKE_WINDOW, STRIKE_WINDOW, 100
        )
    ip_ban_manager._ban_ip_escalating(
        identity, 86400, "threshold_exceeded", grouped="/" in identity
    )


@pytest.mark.parametrize("foreign_seconds", [86400, 60])
def test_both_workers_keep_a_foreign_ban_the_rule_dropped(
    redis_fleet: Fleet, second_worker: SecondWorker, foreign_seconds: int
) -> None:
    redis_fleet.apply(1, [IP])
    assert second_worker.ask(IP) == {IP: True}
    ip_ban_manager.ban_ip(IP, foreign_seconds, "auto_ban")

    redis_fleet.apply(2, [OTHER])

    assert ip_ban_manager.is_ip_banned(IP)
    assert second_worker.ask(IP) == {IP: True}


def test_a_worker_that_never_applied_the_first_set_lifts_the_owned_ban_of_another(
    redis_fleet: Fleet, second_worker: SecondWorker
) -> None:
    assert second_worker.apply(1, [IP]) == {"unban_events": 0}
    assert second_worker.ask(IP) == {IP: True}

    redis_fleet.apply(2, [OTHER])

    assert not ip_ban_manager.is_ip_banned(IP)
    assert second_worker.ask(IP) == {IP: False}


def test_a_worker_restart_between_the_sets_still_lifts_the_owned_ban(
    redis_fleet: Fleet,
) -> None:
    assert redis_fleet.redis is not None
    prefix = redis_fleet.redis.config.redis_prefix
    first = SecondWorker(prefix)
    first.apply(1, [IP])
    first.close()
    second = SecondWorker(prefix)
    try:
        assert second.apply(2, [OTHER]) == {"unban_events": 1}
        assert second.ask(IP) == {IP: False}
    finally:
        second.close()


def test_two_workers_applying_the_next_set_at_once_lift_it_once(
    redis_fleet: Fleet,
) -> None:
    assert redis_fleet.redis is not None
    prefix = redis_fleet.redis.config.redis_prefix
    first, second = SecondWorker(prefix), SecondWorker(prefix)
    try:
        for trial in range(5):
            ip = f"198.51.100.{100 + trial}"
            other = f"198.51.100.{200 + trial}"
            first.apply(1 + 2 * trial, [ip])
            second.apply(1 + 2 * trial, [ip])
            before = int(redis_fleet.redis.get_key(*VERSION) or 0)
            start = time.time() + 0.3
            first.start(f"apply {2 + 2 * trial} {start} {other}")
            second.start(f"apply {2 + 2 * trial} {start} {other}")
            events = [first.answer()["unban_events"], second.answer()["unban_events"]]
            after = int(redis_fleet.redis.get_key(*VERSION) or 0)

            assert after - before == 1
            # The ban lifts once across both workers: the previous trial's ban goes
            # to the worker that applied first, this trial's to whichever reaches
            # Redis first. Which one that is is a coin flip, so only the total counts.
            assert sum(events) == 2 * trial + 1
            assert redis_fleet.redis.get_key("banned_ips", ip) is None
    finally:
        first.close()
        second.close()


def test_a_rule_ban_on_one_address_leaves_the_attacker_identity_of_its_prefix(
    redis_fleet: Fleet, second_worker: SecondWorker
) -> None:
    assert redis_fleet.redis is not None
    redis_fleet.apply(1, [RULE_V6])
    _strike_and_ban_identity(redis_fleet.redis, IDENTITY)
    before = _identity_state(redis_fleet.redis, IDENTITY)
    assert second_worker.ask(ATTACKER) == {ATTACKER: True}

    redis_fleet.apply(2, [OTHER])

    _assert_state_kept(before, _identity_state(redis_fleet.redis, IDENTITY))
    assert ip_ban_manager.is_ip_banned(ATTACKER)
    assert second_worker.ask(ATTACKER) == {ATTACKER: True}


def test_dropping_a_rule_ban_keeps_the_strikes_and_recidive_of_that_address(
    redis_fleet: Fleet, second_worker: SecondWorker
) -> None:
    assert redis_fleet.redis is not None
    redis = redis_fleet.redis
    _strike_and_ban_identity(redis, IP)
    redis.delete("banned_ips", IP)
    redis_fleet.apply(1, [IP])
    before = _identity_state(redis, IP)
    before["identity_ttl"] = 1
    assert second_worker.ask(IP) == {IP: True}

    redis_fleet.apply(2, [OTHER])

    after = _identity_state(redis, IP)
    after["identity_ttl"] = 1
    assert after == before
    assert not ip_ban_manager.is_ip_banned(IP)
    assert second_worker.ask(IP) == {IP: False}


def test_a_rule_that_lists_the_prefix_the_engine_banned_keeps_its_identity_ban(
    redis_fleet: Fleet, second_worker: SecondWorker
) -> None:
    assert redis_fleet.redis is not None
    redis_fleet.apply(1, [IDENTITY])
    _strike_and_ban_identity(redis_fleet.redis, IDENTITY)
    before = _identity_state(redis_fleet.redis, IDENTITY)
    assert second_worker.ask(ATTACKER) == {ATTACKER: True}

    redis_fleet.apply(2, [OTHER])

    _assert_state_kept(before, _identity_state(redis_fleet.redis, IDENTITY))
    assert ip_ban_manager.is_ip_banned(ATTACKER)
    assert second_worker.ask(ATTACKER) == {ATTACKER: True}


def test_a_network_rule_ban_is_deleted_in_both_workers_when_nothing_replaced_it(
    redis_fleet: Fleet, second_worker: SecondWorker
) -> None:
    redis_fleet.apply(1, [NETWORK])
    assert second_worker.ask(INSIDE_NETWORK) == {INSIDE_NETWORK: True}
    assert ip_ban_manager.is_ip_banned(INSIDE_NETWORK)

    redis_fleet.apply(2, [OTHER])

    assert not ip_ban_manager.is_ip_banned(INSIDE_NETWORK)
    assert second_worker.ask(INSIDE_NETWORK) == {INSIDE_NETWORK: False}


def test_a_longer_foreign_network_ban_stays_in_both_workers(
    redis_fleet: Fleet, second_worker: SecondWorker
) -> None:
    redis_fleet.apply(1, [NETWORK])
    assert second_worker.ask(INSIDE_NETWORK) == {INSIDE_NETWORK: True}
    ip_ban_manager.ban_ip(NETWORK, 86400, "auto_ban")

    redis_fleet.apply(2, [OTHER])

    assert ip_ban_manager.is_ip_banned(INSIDE_NETWORK)
    assert second_worker.ask(INSIDE_NETWORK) == {INSIDE_NETWORK: True}


@pytest.mark.parametrize(("target", "probe"), [(IP, IP), (NETWORK, INSIDE_NETWORK)])
def test_a_foreign_ban_held_in_this_process_is_not_seen_by_a_second_worker(
    redis_fleet: Fleet, second_worker: SecondWorker, target: str, probe: str
) -> None:
    redis_fleet.apply(1, [target])
    assert second_worker.ask(probe) == {probe: True}
    with patch.object(
        redis_fleet.redis,
        "write_ban_extending_only",
        MagicMock(side_effect=RuntimeError("redis write failed")),
    ):
        ip_ban_manager.ban_ip(target, 86400, "auto_ban")

    redis_fleet.apply(2, [OTHER])

    assert ip_ban_manager.is_ip_banned(probe)
    assert second_worker.ask(probe) == {probe: False}
