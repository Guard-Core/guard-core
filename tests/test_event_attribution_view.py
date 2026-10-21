import ipaddress
import logging
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.detection_result import DetectionResult
from guard_core.handlers._dynamic_rule_attribution import build_rule_attribution
from guard_core.handlers._ipban_cache import _OperatorNetworks
from guard_core.handlers.ipban_handler import ip_ban_manager
from tests.test_event_attribution import DYNAMIC, OTHER_IP, RULE_IP, _config, _rules


async def test_the_view_ignores_what_it_cannot_parse_or_does_not_own() -> None:
    config = _config(rate_limit=100)
    rules = _rules(ip_blacklist=[RULE_IP], global_rate_limit=5)
    view = build_rule_attribution(rules, config, ["not-an-address", RULE_IP], [], {})

    assert await view.for_ban("unknown", ip_ban_manager) == {}
    assert await view.for_ban(OTHER_IP, ip_ban_manager) == {}
    assert view.for_rate_limit_tier("route", "/x") == {}
    assert view.for_rate_limit_tier("global", "") == DYNAMIC
    assert view.for_cloud_provider("AWS", None) == {}
    assert view.for_pattern(None) == {}
    assert view.for_user_agent_pattern(None) == {}
    assert view.for_country("country_whitelist", "CN") == {}
    assert view.for_emergency_mode() == {}


def test_a_detection_without_an_id_or_a_category_adds_no_event_fields() -> None:
    result = DetectionResult(is_threat=True, trigger_info="x")

    assert SuspiciousActivityCheck._detection_event_fields(result) == {}


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
    from guard_core.core.routing import resolver as resolver_module
    from guard_core.core.routing.context import RoutingContext
    from guard_core.core.routing.resolver import RouteConfigResolver

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


async def test_a_redis_failure_while_reading_ownership_attributes_nothing() -> None:
    redis = MagicMock()
    redis.owned_ban_expiry = AsyncMock(side_effect=RuntimeError("down"))
    monkey = ip_ban_manager.redis_handler
    ip_ban_manager.redis_handler = redis
    try:
        assert (
            await ip_ban_manager.rule_owns_live_ban("banned_ips:203.0.113.5") is False
        )
    finally:
        ip_ban_manager.redis_handler = monkey


async def test_a_repeat_ban_hit_reuses_the_stamp_until_the_interval_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    ip_ban_manager.config = config
    assert await ip_ban_manager.ban_ip(RULE_IP, 3600, "dynamic_rule")
    view = build_rule_attribution(_rules(ip_blacklist=[RULE_IP]), config, [], [], {})
    monkeypatch.setattr(ip_ban_manager, "_VERSION_RECHECK_SECONDS", 0.2)
    lookups: list[str] = []
    original = ip_ban_manager.deciding_ban_entry

    def counting(ip: str) -> tuple[str, float] | None:
        lookups.append(ip)
        return original(ip)

    monkeypatch.setattr(ip_ban_manager, "deciding_ban_entry", counting)

    first = [await view.for_ban(RULE_IP, ip_ban_manager) for _ in range(50)]
    assert first == [DYNAMIC] * 50
    assert lookups == [RULE_IP]

    time.sleep(0.3)
    assert await view.for_ban(RULE_IP, ip_ban_manager) == DYNAMIC
    assert lookups == [RULE_IP, RULE_IP]


async def test_a_stamp_is_kept_under_the_version_it_was_computed_under(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    ip_ban_manager.config = config
    assert await ip_ban_manager.ban_ip(RULE_IP, 3600, "dynamic_rule")
    view = build_rule_attribution(_rules(ip_blacklist=[RULE_IP]), config, [], [], {})
    monkeypatch.setattr(ip_ban_manager, "_ban_version_seen", "v1")
    monkeypatch.setattr(ip_ban_manager, "_VERSION_RECHECK_SECONDS", 60.0)
    computed: list[str] = []

    async def moves_the_version(self: object, ip: str, bans: object) -> dict[str, str]:
        computed.append(ip)
        ip_ban_manager._ban_version_seen = "v2"
        return {"stamp": "under-v1"}

    monkeypatch.setattr(type(view), "_ban_stamp", moves_the_version)

    first = await view.for_ban(RULE_IP, ip_ban_manager)
    second = await view.for_ban(RULE_IP, ip_ban_manager)

    assert first == second == {"stamp": "under-v1"}
    assert computed == [RULE_IP, RULE_IP]
