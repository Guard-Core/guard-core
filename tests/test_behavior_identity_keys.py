"""Every per-client behavior key, in memory and in Redis, keeps its 4.4.0 bytes.

``PINNED_AT_5C38DC89`` was recorded by running the same probe on 5c38dc89 (before
the behavior counters moved to the client identity), through the real
``extract_client_ip`` with a non-canonical peer: uppercase IPv6 hex and an
IPv4-mapped ``::ffff:`` peer. IPv4 and ``ipv6_prefix_length=128`` must reproduce
those bytes; a native IPv6 client at a shorter prefix moves to its network's key
once (its behavior windows restart), which the last tests pin.
"""

import time
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core._utils.ip_extraction import extract_client_ip
from guard_core.handlers._behavior_throttle import ThrottleCheck, trip_marker_key
from guard_core.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard_core.models import SecurityConfig

PINNED_AT_5C38DC89: dict[str, Any] = {
    "2001:DB8::5": {
        "client_ip": "2001:db8::5",
        "memory": {
            "recent": 1,
            "returns": {
                '["return_pattern","status:404",60,5,"log"]|ep': [
                    "2001:db8::5",
                ],
            },
            "usage": {
                '["usage",null,60,5,"log"]|ep': [
                    "2001:db8::5",
                ],
            },
        },
        "redis_reads": [
            [
                "behavior_usage",
                (
                    "behavior:usage:034a7e52c5c9534b709dc1dba403868399b0949f7c193"
                    "3a67325c22077ffc221:e3b38e0aff3c7834c1ed6594ca59f320f3c5e5ab"
                    "36f8c2bea977e52b340fee37"
                ),
            ],
        ],
        "redis_writes": [
            [
                "behavior_usage",
                (
                    "behavior:usage:0e26f370b56256f2c7dc5a6c5b4a43cbdfb8a61961fcd"
                    "697e65896ec1579f9e8:e3b38e0aff3c7834c1ed6594ca59f320f3c5e5ab"
                    "36f8c2bea977e52b340fee37:c59ff86886ace092337d12100e16b260e89"
                    "fa3c197ecc0362a6e2377b41b7b20"
                ),
                (
                    "('behavior:usage:034a7e52c5c9534b709dc1dba403868399b0949f7c1"
                    "933a67325c22077ffc221:e3b38e0aff3c7834c1ed6594ca59f320f3c5e5"
                    "ab36f8c2bea977e52b340fee37', 10000)"
                ),
            ],
            [
                "behavior_returns",
                (
                    "behavior:return:0e26f370b56256f2c7dc5a6c5b4a43cbdfb8a61961fc"
                    "d697e65896ec1579f9e8:e3b38e0aff3c7834c1ed6594ca59f320f3c5e5a"
                    "b36f8c2bea977e52b340fee37:65a328eb77cb3e800576adfc8ff2d7f756"
                    "09bd4513ab0bedc9969c8836351228"
                ),
                "None",
            ],
        ],
    },
    "2001:db8:0:1::5": {
        "client_ip": "2001:db8:0:1::5",
        "memory": {
            "recent": 1,
            "returns": {
                '["return_pattern","status:404",60,5,"log"]|ep': [
                    "2001:db8:0:1::5",
                ],
            },
            "usage": {
                '["usage",null,60,5,"log"]|ep': [
                    "2001:db8:0:1::5",
                ],
            },
        },
        "redis_reads": [
            [
                "behavior_usage",
                (
                    "behavior:usage:034a7e52c5c9534b709dc1dba403868399b0949f7c193"
                    "3a67325c22077ffc221:aa1507709a6d58af42cfac19886c5ecfe6f0d55f"
                    "0952de0ee7df5348eb3b35a3"
                ),
            ],
        ],
        "redis_writes": [
            [
                "behavior_usage",
                (
                    "behavior:usage:0e26f370b56256f2c7dc5a6c5b4a43cbdfb8a61961fcd"
                    "697e65896ec1579f9e8:aa1507709a6d58af42cfac19886c5ecfe6f0d55f"
                    "0952de0ee7df5348eb3b35a3:c59ff86886ace092337d12100e16b260e89"
                    "fa3c197ecc0362a6e2377b41b7b20"
                ),
                (
                    "('behavior:usage:034a7e52c5c9534b709dc1dba403868399b0949f7c1"
                    "933a67325c22077ffc221:aa1507709a6d58af42cfac19886c5ecfe6f0d5"
                    "5f0952de0ee7df5348eb3b35a3', 10000)"
                ),
            ],
            [
                "behavior_returns",
                (
                    "behavior:return:0e26f370b56256f2c7dc5a6c5b4a43cbdfb8a61961fc"
                    "d697e65896ec1579f9e8:aa1507709a6d58af42cfac19886c5ecfe6f0d55"
                    "f0952de0ee7df5348eb3b35a3:65a328eb77cb3e800576adfc8ff2d7f756"
                    "09bd4513ab0bedc9969c8836351228"
                ),
                "None",
            ],
        ],
    },
    "2001:db8::5": {
        "client_ip": "2001:db8::5",
        "memory": {
            "recent": 1,
            "returns": {
                '["return_pattern","status:404",60,5,"log"]|ep': [
                    "2001:db8::5",
                ],
            },
            "usage": {
                '["usage",null,60,5,"log"]|ep': [
                    "2001:db8::5",
                ],
            },
        },
        "redis_reads": [
            [
                "behavior_usage",
                (
                    "behavior:usage:034a7e52c5c9534b709dc1dba403868399b0949f7c193"
                    "3a67325c22077ffc221:e3b38e0aff3c7834c1ed6594ca59f320f3c5e5ab"
                    "36f8c2bea977e52b340fee37"
                ),
            ],
        ],
        "redis_writes": [
            [
                "behavior_usage",
                (
                    "behavior:usage:0e26f370b56256f2c7dc5a6c5b4a43cbdfb8a61961fcd"
                    "697e65896ec1579f9e8:e3b38e0aff3c7834c1ed6594ca59f320f3c5e5ab"
                    "36f8c2bea977e52b340fee37:c59ff86886ace092337d12100e16b260e89"
                    "fa3c197ecc0362a6e2377b41b7b20"
                ),
                (
                    "('behavior:usage:034a7e52c5c9534b709dc1dba403868399b0949f7c1"
                    "933a67325c22077ffc221:e3b38e0aff3c7834c1ed6594ca59f320f3c5e5"
                    "ab36f8c2bea977e52b340fee37', 10000)"
                ),
            ],
            [
                "behavior_returns",
                (
                    "behavior:return:0e26f370b56256f2c7dc5a6c5b4a43cbdfb8a61961fc"
                    "d697e65896ec1579f9e8:e3b38e0aff3c7834c1ed6594ca59f320f3c5e5a"
                    "b36f8c2bea977e52b340fee37:65a328eb77cb3e800576adfc8ff2d7f756"
                    "09bd4513ab0bedc9969c8836351228"
                ),
                "None",
            ],
        ],
    },
    "203.0.113.9": {
        "client_ip": "203.0.113.9",
        "memory": {
            "recent": 1,
            "returns": {
                '["return_pattern","status:404",60,5,"log"]|ep': [
                    "203.0.113.9",
                ],
            },
            "usage": {
                '["usage",null,60,5,"log"]|ep': [
                    "203.0.113.9",
                ],
            },
        },
        "redis_reads": [
            [
                "behavior_usage",
                (
                    "behavior:usage:034a7e52c5c9534b709dc1dba403868399b0949f7c193"
                    "3a67325c22077ffc221:d861b7e91033ebc1c1e8e7af3929010158b3241b"
                    "54ca87ef73e79c32f26400ec"
                ),
            ],
        ],
        "redis_writes": [
            [
                "behavior_usage",
                (
                    "behavior:usage:0e26f370b56256f2c7dc5a6c5b4a43cbdfb8a61961fcd"
                    "697e65896ec1579f9e8:d861b7e91033ebc1c1e8e7af3929010158b3241b"
                    "54ca87ef73e79c32f26400ec:c59ff86886ace092337d12100e16b260e89"
                    "fa3c197ecc0362a6e2377b41b7b20"
                ),
                (
                    "('behavior:usage:034a7e52c5c9534b709dc1dba403868399b0949f7c1"
                    "933a67325c22077ffc221:d861b7e91033ebc1c1e8e7af3929010158b324"
                    "1b54ca87ef73e79c32f26400ec', 10000)"
                ),
            ],
            [
                "behavior_returns",
                (
                    "behavior:return:0e26f370b56256f2c7dc5a6c5b4a43cbdfb8a61961fc"
                    "d697e65896ec1579f9e8:d861b7e91033ebc1c1e8e7af3929010158b3241"
                    "b54ca87ef73e79c32f26400ec:65a328eb77cb3e800576adfc8ff2d7f756"
                    "09bd4513ab0bedc9969c8836351228"
                ),
                "None",
            ],
        ],
    },
    "::ffff:203.0.113.9": {
        "client_ip": "203.0.113.9",
        "memory": {
            "recent": 1,
            "returns": {
                '["return_pattern","status:404",60,5,"log"]|ep': [
                    "203.0.113.9",
                ],
            },
            "usage": {
                '["usage",null,60,5,"log"]|ep': [
                    "203.0.113.9",
                ],
            },
        },
        "redis_reads": [
            [
                "behavior_usage",
                (
                    "behavior:usage:034a7e52c5c9534b709dc1dba403868399b0949f7c193"
                    "3a67325c22077ffc221:d861b7e91033ebc1c1e8e7af3929010158b3241b"
                    "54ca87ef73e79c32f26400ec"
                ),
            ],
        ],
        "redis_writes": [
            [
                "behavior_usage",
                (
                    "behavior:usage:0e26f370b56256f2c7dc5a6c5b4a43cbdfb8a61961fcd"
                    "697e65896ec1579f9e8:d861b7e91033ebc1c1e8e7af3929010158b3241b"
                    "54ca87ef73e79c32f26400ec:c59ff86886ace092337d12100e16b260e89"
                    "fa3c197ecc0362a6e2377b41b7b20"
                ),
                (
                    "('behavior:usage:034a7e52c5c9534b709dc1dba403868399b0949f7c1"
                    "933a67325c22077ffc221:d861b7e91033ebc1c1e8e7af3929010158b324"
                    "1b54ca87ef73e79c32f26400ec', 10000)"
                ),
            ],
            [
                "behavior_returns",
                (
                    "behavior:return:0e26f370b56256f2c7dc5a6c5b4a43cbdfb8a61961fc"
                    "d697e65896ec1579f9e8:d861b7e91033ebc1c1e8e7af3929010158b3241"
                    "b54ca87ef73e79c32f26400ec:65a328eb77cb3e800576adfc8ff2d7f756"
                    "09bd4513ab0bedc9969c8836351228"
                ),
                "None",
            ],
        ],
    },
}

USAGE_RULE = BehaviorRule(rule_type="usage", threshold=5, window=60)
RETURN_RULE = BehaviorRule(
    rule_type="return_pattern", threshold=5, window=60, pattern="status:404"
)


async def _client_ip(peer: str, config: SecurityConfig) -> str:
    request = SimpleNamespace(
        client_host=peer, headers={}, state=SimpleNamespace(), url_path="/x"
    )
    return await extract_client_ip(cast(Any, request), config)


async def _observed(peer: str, **settings: Any) -> dict[str, Any]:
    config = SecurityConfig(enable_redis=False, trusted_proxies=[], **settings)
    client_ip = await _client_ip(peer, config)
    response = MagicMock(status_code=404)
    memory = BehaviorTracker(config)
    await memory.track_endpoint_usage("ep", client_ip, USAGE_RULE)
    await memory.track_return_pattern("ep", client_ip, response, RETURN_RULE)
    in_memory = {
        "recent": memory.get_recent_event_count(client_ip, 300),
        "returns": {k: sorted(v) for k, v in memory.return_patterns.items()},
        "usage": {k: sorted(v) for k, v in memory.usage_counts.items()},
    }
    shared = BehaviorTracker(config)
    handler = AsyncMock()
    handler.record_sliding_window_hit = AsyncMock(return_value=1)
    handler.sum_indexed_window_hits = AsyncMock(return_value=0)
    shared.redis_handler = handler
    await shared.track_endpoint_usage("ep", client_ip, USAGE_RULE)
    await shared.track_return_pattern("ep", client_ip, response, RETURN_RULE)
    await shared.count_recent_rule_hits(client_ip, 300)
    return {
        "client_ip": client_ip,
        "memory": in_memory,
        "redis_reads": [
            [str(call.args[0]), str(call.args[1])]
            for call in handler.sum_indexed_window_hits.call_args_list
        ],
        "redis_writes": [
            [str(call.args[0]), str(call.args[1]), str(call.kwargs.get("index"))]
            for call in handler.record_sliding_window_hit.call_args_list
        ],
    }


@pytest.mark.parametrize("peer", sorted(PINNED_AT_5C38DC89))
async def test_every_behavior_key_is_unchanged_at_prefix_128(peer: str) -> None:
    assert await _observed(peer, ipv6_prefix_length=128) == PINNED_AT_5C38DC89[peer]


@pytest.mark.parametrize("peer", ["203.0.113.9", "::ffff:203.0.113.9"])
async def test_every_ipv4_behavior_key_is_unchanged_at_the_default_prefix(
    peer: str,
) -> None:
    assert await _observed(peer) == PINNED_AT_5C38DC89[peer]


async def test_a_native_ipv6_client_moves_to_its_network_key_at_slash_64() -> None:
    pinned = PINNED_AT_5C38DC89["2001:db8:0:1::5"]

    moved = await _observed("2001:db8:0:1::5")

    assert moved["client_ip"] == pinned["client_ip"]
    assert moved["memory"]["usage"] != pinned["memory"]["usage"]
    assert list(moved["memory"]["usage"].values()) == [["2001:db8:0:1::/64"]]
    assert moved["redis_writes"] != pinned["redis_writes"]


async def test_a_native_ipv6_client_has_recent_events_in_both_stores() -> None:
    moved = await _observed("2001:db8:0:1::5")

    assert moved["memory"]["recent"] == 1


async def test_neighbours_in_one_network_share_the_recent_event_count() -> None:
    config = SecurityConfig(enable_redis=False)
    tracker = BehaviorTracker(config)
    await tracker.track_endpoint_usage("ep", "2001:db8:0:1::5", USAGE_RULE)
    await tracker.track_endpoint_usage("ep", "2001:db8:0:1:ffff::9", USAGE_RULE)

    assert tracker.get_recent_event_count("2001:db8:0:1::77", 300) == 2
    assert tracker.get_recent_event_count("2001:db8:0:2::5", 300) == 0


async def test_the_redis_recent_count_reads_the_identity_index() -> None:
    config = SecurityConfig(enable_redis=False)
    tracker = BehaviorTracker(config)
    handler = AsyncMock()
    handler.record_sliding_window_hit = AsyncMock(return_value=1)
    handler.sum_indexed_window_hits = AsyncMock(return_value=3)
    tracker.redis_handler = handler
    await tracker.track_endpoint_usage("ep", "2001:db8:0:1::5", USAGE_RULE)

    count = await tracker.count_recent_rule_hits("2001:db8:0:1::99", 300)

    written = handler.record_sliding_window_hit.call_args_list[0].kwargs["index"]
    read = handler.sum_indexed_window_hits.call_args_list[0].args[1]
    assert count == 3
    assert read == written[0]


async def _throttle_marker_keys(client_ip: str, **settings: Any) -> list[str]:
    tracker = BehaviorTracker(SecurityConfig(enable_redis=False, **settings))
    rule = BehaviorRule(rule_type="usage", threshold=1, window=60, action="throttle")
    check = ThrottleCheck(rule, "ep", True, 1)
    for _ in range(3):
        await tracker.check_throttle(client_ip, [check], time.time(), False)
    return list(tracker._trip_markers)


@pytest.mark.parametrize("client_ip", ["203.0.113.9", "2001:db8::5"])
async def test_throttle_episode_markers_keep_their_bytes_at_prefix_128(
    client_ip: str,
) -> None:
    rule = BehaviorRule(rule_type="usage", threshold=1, window=60, action="throttle")

    keys = await _throttle_marker_keys(client_ip, ipv6_prefix_length=128)

    assert keys == [trip_marker_key("ep", client_ip, rule)]


async def test_throttle_episode_markers_use_the_network_at_slash_64() -> None:
    rule = BehaviorRule(rule_type="usage", threshold=1, window=60, action="throttle")

    keys = await _throttle_marker_keys("2001:db8:0:1::5")

    assert keys == [trip_marker_key("ep", "2001:db8:0:1::/64", rule)]
