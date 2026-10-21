import ipaddress
import logging
import time
from unittest.mock import MagicMock

import pytest

from guard_core.sync.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.sync.detection_result import DetectionResult
from guard_core.sync.handlers._dynamic_rule_attribution import build_rule_attribution
from guard_core.sync.handlers._ipban_cache import _OperatorNetworks
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from tests.test_sync.test_event_attribution import (
    DYNAMIC,
    OTHER_IP,
    RULE_IP,
    _apply,
    _config,
    _rules,
)


def test_the_view_ignores_what_it_cannot_parse_or_does_not_own() -> None:
    config = _config(rate_limit=100)
    rules = _rules(ip_blacklist=[RULE_IP], global_rate_limit=5)
    view = build_rule_attribution(rules, config, ["not-an-address", RULE_IP], [], {})

    assert view.for_ban("unknown", ip_ban_manager) == {}
    assert view.for_ban(OTHER_IP, ip_ban_manager) == {}
    assert view.for_rate_limit_tier("route", "/x") == {}
    assert view.for_rate_limit_tier("global", "") == DYNAMIC
    assert view.for_cloud_provider("AWS", None) == {}
    assert view.for_pattern(None) == {}
    assert view.for_user_agent_pattern(None) == {}
    assert view.for_country("country_whitelist", "CN") == {}
    assert view.for_emergency_mode() == {}


def test_a_detection_without_an_id_or_a_category_adds_no_event_fields() -> None:
    result = DetectionResult(is_threat=True, trigger_info="x")
    middleware = MagicMock()
    middleware.config = _config()
    check = SuspiciousActivityCheck(middleware)

    assert check._detection_event_fields(result) == {}


def test_the_deciding_ban_entry_follows_the_order_of_the_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = time.time()
    ip_ban_manager.config = _config()
    ip_ban_manager.banned_networks = [
        (ipaddress.ip_network("198.51.100.0/24"), now + 90)
    ]
    ip_ban_manager.banned_ips["198.51.100.7"] = now + 50
    ip_ban_manager.banned_ips["2001:db8:0:1::/64"] = now + 70
    monkeypatch.setattr(
        ip_ban_manager,
        "_operator_networks",
        _OperatorNetworks({ipaddress.ip_network("203.0.113.0/24"): now + 80}),
    )

    assert ip_ban_manager.deciding_ban_entry("198.51.100.7") == (
        "banned_ips:198.51.100.7",
        now + 50,
    )
    assert ip_ban_manager.deciding_ban_entry("198.51.100.8") == (
        "banned_networks:198.51.100.0/24",
        now + 90,
    )
    assert ip_ban_manager.deciding_ban_entry("2001:db8:0:1::5") == (
        "banned_identities:2001:db8:0:1::/64",
        now + 70,
    )
    assert ip_ban_manager.deciding_ban_entry("203.0.113.9") == (
        "banned_networks:203.0.113.0/24",
        now + 80,
    )
    assert ip_ban_manager.deciding_ban_entry("192.0.2.1") is None
    assert ip_ban_manager.deciding_ban_entry("unknown") is None


def test_the_view_still_exposes_the_owned_networks_and_provider_names() -> None:
    rules = _rules(
        blocked_cloud_providers={"AWS", "GCP:!us-central1"},
        ip_blacklist=[RULE_IP, "198.51.100.0/24"],
    )
    config = _config(block_cloud_providers={"Azure"})
    view = build_rule_attribution(
        rules,
        config,
        [RULE_IP, "198.51.100.0/24"],
        [],
        {"block_cloud_providers": {"Azure"}},
    )

    assert {str(n) for n in view.ban_networks} == {RULE_IP + "/32", "198.51.100.0/24"}
    assert view.cloud_providers == {"AWS", "GCP"}
    assert view.static_cloud_providers == {"Azure"}


def test_cloud_membership_and_overlap_use_the_provider_and_region_of_the_selector() -> (
    None
):
    config = _config()
    carved = build_rule_attribution(
        _rules(blocked_cloud_providers={"GCP:!us-central1"}), config, [], [], {}
    )
    assert carved.for_cloud_provider("GCP", "us-central1") == {}
    assert carved.for_cloud_provider("GCP", "europe-west1") == DYNAMIC
    assert carved.for_cloud_provider("GCP", None) == DYNAMIC
    assert carved.for_cloud_provider("AWS", None) == {}

    against_static_carve_out = build_rule_attribution(
        _rules(blocked_cloud_providers={"GCP"}),
        config,
        [],
        [],
        {"block_cloud_providers": {"GCP:!us-central1"}},
    )
    assert against_static_carve_out.for_cloud_provider("GCP", "us-central1") == DYNAMIC
    assert against_static_carve_out.for_cloud_provider("GCP", "europe-west1") == {
        **DYNAMIC,
        "matched_rule_overlaps_static": True,
    }


def test_the_per_request_cover_check_does_not_go_through_the_attribution_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = time.time()
    networks = _OperatorNetworks({ipaddress.ip_network("203.0.113.0/24"): now + 60})

    def forbidden(*_args: object) -> None:
        raise AssertionError("covers must stay one pass, no extra call per request")

    monkeypatch.setattr(networks, "covering", forbidden)

    assert networks.covers(ipaddress.ip_address("203.0.113.9"), now) is True
    assert networks.covers(ipaddress.ip_address("192.0.2.9"), now) is False


def test_the_process_record_of_a_rule_write_can_be_read_and_pruned() -> None:
    ip_ban_manager._rule_owned_expiries = {"banned_ips:a": 1.0, "banned_ips:b": 2.0}

    assert ip_ban_manager.rule_written_expiry("banned_ips:a") == 1.0
    ip_ban_manager.forget_rule_written_except(["banned_ips:b"])

    assert ip_ban_manager.rule_written_expiry("banned_ips:a") is None
    assert ip_ban_manager.rule_written_expiry("banned_ips:b") == 2.0
    ip_ban_manager._rule_owned_expiries = {}


def test_a_request_without_a_route_list_does_not_run_the_selector_merge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from guard_core.sync.core.routing import resolver as resolver_module
    from guard_core.sync.core.routing.context import RoutingContext
    from guard_core.sync.core.routing.resolver import RouteConfigResolver

    def forbidden(*_args: object) -> set[str]:
        raise AssertionError("no route list, no merge on the request path")

    monkeypatch.setattr(resolver_module, "merge_cloud_selectors", forbidden)
    config = _config(block_cloud_providers={"GCP"})
    resolver = RouteConfigResolver(
        RoutingContext(
            config=config, logger=logging.getLogger("wp23"), guard_decorator=None
        )
    )

    assert resolver.get_cloud_providers_to_check(None) == ["GCP"]


def test_a_redis_failure_while_reading_ownership_attributes_nothing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from guard_core.sync.handlers import _ipban_rule_revoke

    _ipban_rule_revoke._attribution_failure_samples.clear()
    redis = MagicMock()
    redis.owned_ban_state = MagicMock(side_effect=RuntimeError("down"))
    monkey = ip_ban_manager.redis_handler
    ip_ban_manager.redis_handler = redis
    try:
        with caplog.at_level("WARNING"):
            verdict = ip_ban_manager.rule_owns_live_ban("banned_ips:203.0.113.5")
    finally:
        ip_ban_manager.redis_handler = monkey

    assert verdict is False
    redis.owned_ban_state.assert_called_once_with("banned_ips", "203.0.113.5")
    assert [
        record.message
        for record in caplog.records
        if "Ban attribution skipped" in record.message
    ] == ["Ban attribution skipped, Redis failed: down"]


def test_the_kept_ownership_answers_are_dropped_when_the_cap_is_reached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from guard_core.sync.handlers import _ipban_rule_revoke

    redis = MagicMock()
    redis.owned_ban_state = MagicMock(return_value=(None, None))
    monkeypatch.setattr(ip_ban_manager, "redis_handler", redis)
    monkeypatch.setattr(ip_ban_manager, "_rule_owner_answers", {})
    monkeypatch.setattr(_ipban_rule_revoke, "_MAX_OWNER_ANSWERS", 2)

    for key in ("203.0.113.1", "203.0.113.2", "203.0.113.3"):
        assert ip_ban_manager.rule_owns_live_ban(f"banned_ips:{key}") is False

    assert list(ip_ban_manager._rule_owner_answers) == ["banned_ips:203.0.113.3"]


def test_the_kept_ban_stamps_are_dropped_when_the_cap_is_reached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from guard_core.sync.handlers import _dynamic_rule_attribution

    config = _config()
    ip_ban_manager.config = config
    view = build_rule_attribution(_rules(ip_blacklist=[RULE_IP]), config, [], [], {})
    monkeypatch.setattr(_dynamic_rule_attribution, "_MAX_BAN_STAMPS", 2)

    for address in (RULE_IP, OTHER_IP, "198.51.100.23"):
        view.for_ban(address, ip_ban_manager)

    assert list(view._ban_stamps) == ["198.51.100.23"]


def test_a_user_agent_no_listed_pattern_matches_carries_nothing() -> None:
    from guard_core.sync._utils.rule_attribution import user_agent_attribution

    _apply(_config(), _rules(blocked_user_agents=["wp23bot"]))

    assert user_agent_attribution("wp23bot/1.0", ["wp23bot"]) == DYNAMIC
    assert user_agent_attribution("Mozilla/5.0", ["wp23bot", "other"]) == {}


def test_a_bracketed_client_address_still_gets_the_rules_ban_stamp() -> None:
    config = _config()
    ip_ban_manager.config = config
    assert ip_ban_manager.ban_ip("2001:db8::5", 3600, "dynamic_rule")
    view = build_rule_attribution(
        _rules(ip_blacklist=["2001:db8::5"]), config, [], [], {}
    )

    assert view.for_ban("[2001:db8::5]", ip_ban_manager) == DYNAMIC


def test_a_repeat_ban_hit_reuses_the_stamp_until_the_interval_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    ip_ban_manager.config = config
    assert ip_ban_manager.ban_ip(RULE_IP, 3600, "dynamic_rule")
    view = build_rule_attribution(_rules(ip_blacklist=[RULE_IP]), config, [], [], {})
    monkeypatch.setattr(ip_ban_manager, "_VERSION_RECHECK_SECONDS", 0.2)
    lookups: list[str] = []
    original = ip_ban_manager.deciding_ban_entry

    def counting(ip: str) -> tuple[str, float] | None:
        lookups.append(ip)
        return original(ip)

    monkeypatch.setattr(ip_ban_manager, "deciding_ban_entry", counting)

    first = [view.for_ban(RULE_IP, ip_ban_manager) for _ in range(50)]
    assert first == [DYNAMIC] * 50
    assert lookups == [RULE_IP]

    time.sleep(0.3)
    assert view.for_ban(RULE_IP, ip_ban_manager) == DYNAMIC
    assert lookups == [RULE_IP, RULE_IP]


def test_a_stamp_is_kept_under_the_version_it_was_computed_under(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    ip_ban_manager.config = config
    assert ip_ban_manager.ban_ip(RULE_IP, 3600, "dynamic_rule")
    view = build_rule_attribution(_rules(ip_blacklist=[RULE_IP]), config, [], [], {})
    monkeypatch.setattr(ip_ban_manager, "_ban_version_seen", "v1")
    monkeypatch.setattr(ip_ban_manager, "_VERSION_RECHECK_SECONDS", 60.0)
    computed: list[str] = []

    def moves_the_version(self: object, ip: str, bans: object) -> dict[str, str]:
        computed.append(ip)
        ip_ban_manager._ban_version_seen = "v2"
        return {"stamp": "under-v1"}

    monkeypatch.setattr(type(view), "_ban_stamp", moves_the_version)

    first = view.for_ban(RULE_IP, ip_ban_manager)
    second = view.for_ban(RULE_IP, ip_ban_manager)

    assert first == second == {"stamp": "under-v1"}
    assert computed == [RULE_IP, RULE_IP]
