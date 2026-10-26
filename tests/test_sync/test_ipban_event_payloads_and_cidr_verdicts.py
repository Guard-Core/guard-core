import logging
import time
from collections.abc import Generator
from ipaddress import ip_network
from unittest.mock import MagicMock, Mock

import pytest
from cachetools import TTLCache

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers._ipban_cache import _BanStore
from guard_core.sync.handlers._ipban_rule_revoke import REVOKE_DELETED
from guard_core.sync.handlers.ipban_handler import IPBanManager

LOGGER = "guard_core.sync.handlers.ipban"


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    IPBanManager._instance = None
    yield
    IPBanManager._instance = None


def _manager(trusted: tuple[str, ...] = ()) -> IPBanManager:
    manager = IPBanManager()
    manager.redis_handler = None
    manager.config = SyncSecurityConfig(enable_redis=False, trusted_proxies=trusted)
    manager.agent_handler = Mock(send_event=MagicMock())
    return manager


def _event(manager: IPBanManager) -> MagicMock:
    manager.agent_handler.send_event.assert_called_once()
    event: MagicMock = manager.agent_handler.send_event.call_args.args[0]
    return event


def _messages(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records]


def test_an_exact_ban_event_carries_the_ban_facts() -> None:
    manager = _manager()

    manager.ban_ip("203.0.113.9", 600, "rate_limit_exceeded")

    event = _event(manager)
    assert event.event_type == "ip_banned"
    assert event.ip_address == "203.0.113.9"
    assert event.action_taken == "banned"
    assert event.reason == "rate_limit_exceeded"
    assert event.handler_name == "ip_ban"
    assert event.metadata == {"duration": 600}


def test_a_cidr_ban_event_names_the_normalised_network() -> None:
    manager = _manager()

    manager.ban_ip("203.0.113.77/24", 300, "operator")

    event = _event(manager)
    assert event.ip_address == "203.0.113.0/24"
    assert event.metadata == {"duration": 300}
    assert manager.banned_networks[0][0] == ip_network("203.0.113.0/24")


def test_a_recidive_ban_event_carries_the_count_and_logs_the_escalation(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager()

    with caplog.at_level(logging.INFO, logger=LOGGER):
        manager._store_ban("banned_ips", "203.0.113.9", 900, "x", 3)

    assert _event(manager).metadata == {"duration": 900, "recidive_count": 3}
    assert "Banned 203.0.113.9 for 900 seconds (ban 3 within the recidive window)" in (
        _messages(caplog)
    )


def test_the_refusal_event_reason_and_metadata() -> None:
    manager = _manager()

    manager.ban_ip("127.0.0.1", 600, "why")

    event = _event(manager)
    assert event.event_type == "ip_ban_refused"
    assert event.action_taken == "ban_refused"
    assert event.handler_name == "ip_ban"
    assert event.reason == (
        "Refused to ban 127.0.0.1: loopback would self-DoS this deployment"
    )
    assert event.metadata == {
        "duration": 600,
        "refusal": "loopback",
        "ban_reason": "why",
    }


def test_the_evicted_event_states_the_remaining_time_and_capacity() -> None:
    manager = _manager()

    manager._send_ban_evicted_event(
        manager.agent_handler, "203.0.113.9", time.time() + 100, 4, 50
    )

    event = _event(manager)
    assert event.event_type == "ip_ban_evicted"
    assert event.ip_address == "203.0.113.9"
    assert event.action_taken == "ban_evicted"
    assert event.handler_name == "ip_ban"
    assert event.reason == (
        "An unexpired ban was evicted because the in-memory ban store is full"
    )
    assert set(event.metadata) == {"remaining_seconds", "evictions", "capacity"}
    assert 98 <= event.metadata["remaining_seconds"] <= 100
    assert event.metadata["evictions"] == 4
    assert event.metadata["capacity"] == 50


def test_the_evicted_event_never_reports_negative_remaining_time() -> None:
    manager = _manager()

    manager._send_ban_evicted_event(
        manager.agent_handler, "203.0.113.9", time.time() - 500, 1, 5
    )

    assert _event(manager).metadata["remaining_seconds"] == 0


def test_pending_evictions_are_reported_once_with_the_store_capacity() -> None:
    manager = _manager()
    manager.evicted_to_report = [("203.0.113.9", time.time() + 60, 7)]
    assert isinstance(manager.banned_ips, _BanStore)
    capacity = manager.banned_ips.maxsize

    manager._report_evictions(manager.agent_handler)

    event = _event(manager)
    assert event.metadata["capacity"] == capacity
    assert event.metadata["evictions"] == 7
    assert manager.evicted_to_report == []


def test_the_capacity_falls_back_to_the_local_cap_for_a_plain_mapping() -> None:
    manager = _manager()
    manager.banned_ips = {}
    manager.evicted_to_report = [("203.0.113.9", time.time() + 60, 1)]

    manager._report_evictions(manager.agent_handler)

    assert _event(manager).metadata["capacity"] == manager.MAX_LOCAL_BANS


def test_the_capacity_is_the_store_maxsize_when_it_has_one() -> None:
    manager = _manager()
    manager.banned_ips = TTLCache(maxsize=7, ttl=60)
    manager.evicted_to_report = [("203.0.113.9", time.time() + 60, 1)]

    manager._report_evictions(manager.agent_handler)

    assert manager.MAX_LOCAL_BANS != 7
    assert _event(manager).metadata["capacity"] == 7


def test_an_unban_event_carries_the_action_and_the_details() -> None:
    manager = _manager()

    manager._send_unban_event(
        manager.agent_handler, "203.0.113.9", "manual", {"by": "ops"}
    )

    event = _event(manager)
    assert event.event_type == "ip_unbanned"
    assert event.ip_address == "203.0.113.9"
    assert event.action_taken == "unbanned"
    assert event.reason == "manual"
    assert event.handler_name == "ip_ban"
    assert event.metadata == {"action": "unban", "by": "ops"}


def test_an_unban_event_without_details_holds_only_the_action() -> None:
    manager = _manager()

    manager._send_unban_event(manager.agent_handler, "203.0.113.9", "manual")

    assert _event(manager).metadata == {"action": "unban"}


@pytest.mark.parametrize(
    ("method", "arguments", "text"),
    [
        (
            "_send_ban_event",
            ("203.0.113.9", 60, "r"),
            "Failed to send ban event to agent: boom",
        ),
        (
            "_send_ban_refused_event",
            ("203.0.113.9", 60, "r", "loopback"),
            "Failed to send ban refused event to agent: boom",
        ),
        (
            "_send_ban_evicted_event",
            ("203.0.113.9", 1.0, 1, 1),
            "Failed to send ban evicted event to agent: boom",
        ),
        (
            "_send_unban_event",
            ("203.0.113.9", "r"),
            "Failed to send unban event to agent: boom",
        ),
    ],
)
def test_an_agent_failure_is_logged_with_its_cause(
    method: str,
    arguments: tuple[str | int | float, ...],
    text: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager()
    manager.agent_handler.send_event.side_effect = RuntimeError("boom")

    with caplog.at_level(logging.ERROR, logger=LOGGER):
        getattr(manager, method)(manager.agent_handler, *arguments)

    assert text in _messages(caplog)


def test_a_zero_duration_is_rejected_with_the_value_in_the_message() -> None:
    manager = _manager()

    with pytest.raises(ValueError, match=r"^ban duration must be positive, got 0$"):
        manager.ban_ip("203.0.113.9", 0)
    with pytest.raises(ValueError, match=r"^ban duration must be positive, got -5$"):
        manager.ban_ip("203.0.113.9", -5)


def test_an_invalid_cidr_is_rejected_naming_the_input() -> None:
    manager = _manager()

    with pytest.raises(ValueError, match=r"^Invalid CIDR network '1.2.3.4/99': "):
        manager._ban_cidr("1.2.3.4/99", 60, "r")


def test_an_invalid_exact_ip_is_rejected_naming_the_input() -> None:
    manager = _manager()

    with pytest.raises(ValueError, match=r"^Invalid IP address 'nope': "):
        manager.ban_ip("nope", 60)


def test_an_invalid_identity_is_rejected_naming_the_input() -> None:
    manager = _manager()

    with pytest.raises(ValueError, match=r"^Invalid identity 'nope': "):
        manager.ban_ip("nope", 60, grouped=True)


def test_a_grouped_ban_is_stored_under_the_normalised_identity() -> None:
    manager = _manager()

    manager.ban_ip("203.0.113.77/24", 60, grouped=True)

    assert "203.0.113.0/24" in manager.banned_ips
    assert _event(manager).ip_address == "203.0.113.0/24"


def test_a_redis_write_failure_keeps_the_ban_in_this_process_and_says_so(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager()
    manager.redis_handler = Mock(
        write_ban_extending_only=MagicMock(side_effect=RuntimeError("down"))
    )

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        manager.ban_ip("203.0.113.9", 60)

    assert (
        "Redis unavailable (request failed): the ban of 203.0.113.9 is kept in "
        "this process only"
    ) in _messages(caplog)
    assert manager.banned_ips["203.0.113.9"] > time.time()


def test_a_redis_cidr_write_failure_keeps_the_network_and_says_so(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager()
    manager.redis_handler = Mock(
        write_ban_extending_only=MagicMock(side_effect=RuntimeError("down"))
    )

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        manager.ban_ip("203.0.113.0/24", 60)

    assert (
        "Redis unavailable (request failed): the ban of 203.0.113.0/24 is kept in "
        "this process only"
    ) in _messages(caplog)
    assert [net for net, _ in manager.banned_networks] == [ip_network("203.0.113.0/24")]


def test_a_redis_cidr_write_passes_the_version_and_ownership() -> None:
    manager = _manager()
    write = MagicMock(return_value=0.0)
    manager.redis_handler = Mock(write_ban_extending_only=write)

    manager.ban_ip("203.0.113.0/24", 60, "dynamic_rule")

    args, kwargs = write.call_args_list[-1]
    assert args[0] == "banned_networks"
    assert args[1] == "203.0.113.0/24"
    assert args[3] == 60
    assert kwargs == {
        "version": ("ban_version", "counter"),
        "advance_version": True,
        "rule_owned": True,
    }


def test_a_private_range_ban_warns_about_the_reverse_proxy(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager()

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        manager.ban_ip("192.168.7.7", 60)

    assert (
        "Banning private IP range 192.168.7.7: if requests reach this service "
        "through a reverse proxy, this IP may be the proxy and the ban will block "
        "ALL users. Verify config.trusted_proxies lists the proxy IP(s); see "
        "docs/configuration/security-config.md"
    ) in _messages(caplog)


def test_a_public_ban_does_not_warn_about_private_ranges(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager()

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        manager.ban_ip("8.8.8.8", 60)

    assert not [m for m in _messages(caplog) if "private IP range" in m]


def test_a_ban_under_a_rule_whitelist_is_refused_and_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager()
    manager.set_rule_exempt_ips(["203.0.113.0/24"])

    with caplog.at_level(logging.INFO, logger=LOGGER):
        applied = manager.ban_ip("203.0.113.9", 60)

    assert applied is False
    assert (
        "Refused to ban 203.0.113.9: covered by an active dynamic rule "
        "ip_whitelist entry"
    ) in _messages(caplog)


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("127.0.0.1", "loopback"),
        ("127.0.0.0/8", "loopback"),
        ("::1", "loopback"),
        ("0.0.0.0/0", "loopback"),
        ("::/0", "loopback"),
        ("10.9.9.9", "trusted_proxy"),
        ("10.0.0.0/8", "trusted_proxy"),
        ("2001:db8::5", "trusted_proxy"),
        ("2001:db8::/32", "trusted_proxy"),
        ("203.0.113.9", None),
        ("203.0.113.0/24", None),
        ("2606:4700::1", None),
        ("not-an-ip", None),
        ("1.2.3.4/99", None),
    ],
)
def test_the_self_dos_verdict_per_target(target: str, expected: str | None) -> None:
    manager = _manager(trusted=("10.9.0.0/16", "2001:db8::/48"))

    assert manager._self_dos_refusal_reason(target) == expected


def test_target_network_of_an_address_is_a_single_host_network() -> None:
    manager = _manager()

    assert manager._target_network("203.0.113.9") == ip_network("203.0.113.9/32")
    assert manager._target_network("203.0.113.77/24") == ip_network("203.0.113.0/24")
    assert manager._target_network("::1") == ip_network("::1/128")
    assert manager._target_network("bad") is None
    assert manager._target_network("bad/24") is None


def test_trusted_proxy_networks_are_empty_without_a_config() -> None:
    manager = _manager()
    manager.config = None

    assert manager._trusted_proxy_networks() == []


def test_a_refusal_is_reported_only_once_per_window() -> None:
    manager = _manager()

    manager.ban_ip("127.0.0.1", 600)
    manager.ban_ip("127.0.0.1", 600)

    manager.agent_handler.send_event.assert_called_once()
    assert manager.refused_ban_reported_until["127.0.0.1"] > time.time() + 590


def test_disown_does_nothing_without_redis() -> None:
    manager = _manager()

    manager.disown_rule_ban("203.0.113.9")

    assert manager.redis_handler is None


def test_disown_routes_an_address_and_a_cidr_to_their_namespaces() -> None:
    manager = _manager()
    disown = MagicMock()
    manager.redis_handler = Mock(disown_ban=disown)

    manager.disown_rule_ban("203.0.113.9")
    manager.disown_rule_ban("203.0.113.77/24")

    assert [c.args for c in disown.call_args_list] == [
        ("banned_ips", "203.0.113.9"),
        ("banned_networks", "203.0.113.0/24"),
    ]


def test_purge_counts_every_outcome_and_drops_the_local_copies(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager()
    members = [
        "pfx:banned_ips:203.0.113.1",
        "pfx:banned_networks:203.0.113.0/24",
        "pfx:banned_ips:203.0.113.2",
        "pfx:banned_ips:203.0.113.3",
        "pfx:banned_ips:203.0.113.4",
        "pfx:banned_ips:203.0.113.5",
        "pfx:banned_ips:203.0.113.6",
    ]
    outcomes: dict[str, int | Exception] = {
        members[0]: 0,
        members[1]: 1,
        members[2]: 2,
        members[3]: 3,
        members[4]: RuntimeError("scripted"),
        members[5]: 0,
        members[6]: RuntimeError("again"),
    }

    def purge(member: str) -> int:
        result = outcomes[member]
        if isinstance(result, Exception):
            raise result
        return result

    manager.redis_handler = Mock(
        config=Mock(redis_prefix="pfx:"),
        owned_ban_members=MagicMock(return_value=members),
        purge_owned_ban=purge,
        incr=MagicMock(),
    )
    manager.banned_ips["203.0.113.1"] = time.time() + 99
    manager.banned_ips["203.0.113.4"] = time.time() + 99
    manager.banned_ips["203.0.113.5"] = time.time() + 99
    manager.banned_networks = [(ip_network("203.0.113.0/24"), time.time() + 99)]

    with caplog.at_level(logging.ERROR, logger=LOGGER):
        counts = manager.purge_rule_owned_bans()

    assert counts == {
        "gone": 2,
        "deleted": 1,
        "rewritten": 1,
        "kept": 1,
        "failed": 2,
    }
    assert "203.0.113.5" not in manager.banned_ips
    assert "Purging the rule ban pfx:banned_ips:203.0.113.4 failed: scripted" in (
        _messages(caplog)
    )
    assert "203.0.113.1" not in manager.banned_ips
    assert "203.0.113.4" in manager.banned_ips
    assert manager.banned_networks == []
    manager.redis_handler.incr.assert_called_once_with("ban_version", "counter")


def test_purge_without_redis_returns_all_zero_counts() -> None:
    manager = _manager()

    assert manager.purge_rule_owned_bans() == {
        "gone": 0,
        "deleted": 0,
        "rewritten": 0,
        "kept": 0,
        "failed": 0,
    }


def test_initialize_agent_stores_the_agent_handler() -> None:
    manager = _manager()
    agent = Mock()

    manager.initialize_agent(agent)

    assert manager.agent_handler is agent


def test_a_ban_without_a_reason_is_recorded_as_threshold_exceeded() -> None:
    manager = _manager()

    manager.ban_ip("203.0.113.9", 60)

    assert _event(manager).reason == "threshold_exceeded"


def test_an_escalating_ban_without_a_reason_is_threshold_exceeded() -> None:
    manager = _manager()

    assert manager._ban_ip_escalating("203.0.113.9", 60) == 60

    assert _event(manager).reason == "threshold_exceeded"


def test_an_escalating_ban_is_not_grouped_unless_asked() -> None:
    manager = _manager()

    manager._ban_ip_escalating("2001:db8:0:1::5", 60)

    assert list(manager.banned_ips) == ["2001:db8:0:1::5"]


def test_a_public_ban_returns_true_and_a_refused_one_false() -> None:
    manager = _manager()

    assert manager.ban_ip("203.0.113.9", 60) is True
    assert manager.ban_ip("127.0.0.1", 60) is False


def test_a_ban_does_not_escalate_unless_the_engine_asks() -> None:
    manager = _manager()
    manager.config = SyncSecurityConfig(enable_redis=False, enable_recidive=True)

    for _ in range(3):
        manager.ban_ip("8.8.8.8", 100)

    assert manager.banned_ips["8.8.8.8"] - time.time() <= 100


def test_an_escalating_grouped_ban_lands_in_the_identity_namespace() -> None:
    manager = _manager()
    manager.config = SyncSecurityConfig(enable_redis=False, enable_recidive=True)
    write = MagicMock(return_value=time.time() + 100)
    manager.redis_handler = Mock(
        write_ban_extending_only=write, get_key=MagicMock(return_value=None)
    )

    manager._ban_ip_escalating("2001:db8:0:1::5/64", 100, grouped=True)

    assert write.call_args_list[-1].args[0] == "banned_identities"
    assert write.call_args_list[-1].args[1] == "2001:db8:0:1::/64"


def test_an_escalating_exact_ban_lands_in_the_ip_namespace() -> None:
    manager = _manager()
    manager.config = SyncSecurityConfig(enable_redis=False, enable_recidive=True)
    write = MagicMock(return_value=time.time() + 100)
    manager.redis_handler = Mock(
        write_ban_extending_only=write, get_key=MagicMock(return_value=None)
    )

    manager._ban_ip_escalating("8.8.8.8", 100)

    assert write.call_args_list[-1].args[0] == "banned_ips"
    assert write.call_args_list[-1].args[1] == "8.8.8.8"


def test_a_grouped_ban_is_written_to_redis_under_identities() -> None:
    manager = _manager()
    write = MagicMock(return_value=time.time() + 60)
    manager.redis_handler = Mock(write_ban_extending_only=write)

    manager.ban_ip("2001:db8:0:1::5/64", 60, grouped=True)

    assert write.call_args_list[-1].args[0] == "banned_identities"
    assert write.call_args_list[-1].args[1] == "2001:db8:0:1::/64"


@pytest.mark.parametrize(
    ("reason", "owned"), [("dynamic_rule", True), ("rate_limit_exceeded", False)]
)
def test_a_redis_ban_write_says_whether_a_rule_owns_it(
    reason: str, owned: bool
) -> None:
    manager = _manager()
    write = MagicMock(return_value=time.time() + 60)
    manager.redis_handler = Mock(write_ban_extending_only=write)

    manager.ban_ip("203.0.113.9", 60, reason)

    assert write.call_args_list[-1].kwargs["rule_owned"] is owned


@pytest.mark.parametrize(
    ("reason", "targets"),
    [("dynamic_rule", ["203.0.113.9"]), ("rate_limit_exceeded", [])],
)
def test_a_memory_exact_ban_is_rule_owned_only_for_a_rule_reason(
    reason: str, targets: list[str]
) -> None:
    manager = _manager()

    manager.ban_ip("203.0.113.9", 60, reason)

    assert manager.owned_rule_ban_targets() == targets


@pytest.mark.parametrize(
    ("reason", "targets"),
    [("dynamic_rule", ["203.0.113.0/24"]), ("operator", [])],
)
def test_a_memory_cidr_ban_is_rule_owned_only_for_a_rule_reason(
    reason: str, targets: list[str]
) -> None:
    manager = _manager()

    manager.ban_ip("203.0.113.0/24", 60, reason)

    assert manager.owned_rule_ban_targets() == targets


@pytest.mark.parametrize(
    ("reason", "targets"),
    [("dynamic_rule", ["203.0.113.0/24"]), ("operator", [])],
)
def test_a_cidr_ban_kept_after_a_redis_failure_keeps_its_ownership(
    reason: str, targets: list[str]
) -> None:
    manager = _manager()
    manager.redis_handler = Mock(
        write_ban_extending_only=MagicMock(side_effect=RuntimeError("down")),
        owned_ban_members=MagicMock(return_value=[]),
        config=Mock(redis_prefix="p:"),
    )

    manager.ban_ip("203.0.113.0/24", 60, reason)

    assert manager.owned_rule_ban_targets() == targets


def test_a_memory_cidr_ban_lasts_for_the_duration_from_now() -> None:
    manager = _manager()
    before = time.time()

    manager.ban_ip("203.0.113.0/24", 500, "operator")

    expiry = manager.banned_networks[0][1]
    assert before + 500 <= expiry <= time.time() + 500


def test_a_redis_failed_cidr_ban_lasts_for_the_duration_from_now() -> None:
    manager = _manager()
    manager.redis_handler = Mock(
        write_ban_extending_only=MagicMock(side_effect=RuntimeError("down"))
    )
    before = time.time()

    manager.ban_ip("203.0.113.0/24", 500, "operator")

    expiry = manager.banned_networks[0][1]
    assert before + 500 <= expiry <= time.time() + 500


def test_rebanning_a_network_keeps_one_entry_with_the_longest_expiry() -> None:
    manager = _manager()
    manager.ban_ip("203.0.113.0/24", 1000, "operator")
    longest = manager.banned_networks[0][1]
    manager.ban_ip("198.51.100.0/24", 50, "operator")

    manager.ban_ip("203.0.113.0/24", 10, "operator")

    by_network = dict(manager.banned_networks)
    assert len(manager.banned_networks) == 2
    assert by_network[ip_network("203.0.113.0/24")] == longest
    assert ip_network("198.51.100.0/24") in by_network


def test_a_ban_that_redis_extended_is_kept_for_the_extended_time() -> None:
    manager = _manager()
    manager.redis_handler = Mock(
        write_ban_extending_only=MagicMock(return_value=time.time() + 5000)
    )
    manager.LOCAL_CACHE_TTL_CAP_SECONDS = 10_000

    manager.ban_ip("203.0.113.9", 60)

    assert manager.banned_ips["203.0.113.9"] > time.time() + 4000


def test_a_ban_held_in_memory_only_is_marked_memory_only() -> None:
    manager = _manager()

    manager.ban_ip("203.0.113.9", 60)

    assert isinstance(manager.banned_ips, _BanStore)
    assert manager.banned_ips.is_memory_only("203.0.113.9")


def test_a_ban_backed_by_redis_is_not_marked_memory_only() -> None:
    manager = _manager()
    manager.redis_handler = Mock(
        write_ban_extending_only=MagicMock(return_value=time.time() + 60)
    )

    manager.ban_ip("203.0.113.9", 60)

    assert isinstance(manager.banned_ips, _BanStore)
    assert not manager.banned_ips.is_memory_only("203.0.113.9")


def test_a_fresh_manager_has_no_config_agent_or_redis() -> None:
    manager = IPBanManager()

    assert manager.config is None
    assert manager.agent_handler is None
    assert manager.redis_handler is None


def test_a_due_version_recheck_without_redis_keeps_the_cached_ban(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = _manager()
    manager._ban_version_checked_at = 0.0

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        assert manager._cached_positive_survives(time.time()) is True

    assert _messages(caplog) == []


def test_lifted_rule_bans_without_an_agent_send_no_event() -> None:
    manager = _manager()
    manager.agent_handler = None

    manager.settle_rule_revocations([("203.0.113.9", REVOKE_DELETED)])

    assert manager.agent_handler is None
