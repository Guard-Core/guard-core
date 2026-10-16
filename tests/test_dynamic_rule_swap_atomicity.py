import sys
import threading
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

from guard_core.models import DynamicRules, SecurityConfig
from guard_core.protocols.geo_ip_protocol import GeoIPHandler
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager

SWAPS = 10_000
FIELDS = (
    "rate_limit",
    "rate_limit_window",
    "auto_ban_threshold",
    "auto_ban_duration",
    "blocked_countries",
    "block_cloud_providers",
    "exempt_ips",
    "emergency_mode",
    "enable_rate_limiting",
    "endpoint_rate_limits",
)


def _rules(index: int, **overrides: Any) -> DynamicRules:
    base: dict[str, Any] = {
        "rule_id": f"R{index}",
        "version": 1,
        "timestamp": datetime.now(timezone.utc),
        "global_rate_limit": 100 * index,
        "global_rate_window": 10 * index,
        "auto_ban_threshold": 20 * index,
        "auto_ban_duration": 300 * index,
        "blocked_countries": ["AA" if index == 1 else "BB"],
        "blocked_cloud_providers": {"AWS" if index == 1 else "Azure"},
        "ip_whitelist": [f"198.51.100.{index}"],
        "enable_rate_limiting": index == 1,
        "endpoint_rate_limits": {f"/e{index}": (index, index)},
    }
    base.update(overrides)
    return DynamicRules(**base)


def _signature(source: Any) -> tuple[Any, ...]:
    return tuple(source[name] for name in FIELDS)


def test_a_swap_is_never_observed_half_done_by_a_concurrent_reader() -> None:
    DynamicRuleManager._instance = None
    config = SecurityConfig(
        enable_redis=False,
        enable_agent=True,
        agent_api_key="test-api-key",
        enable_dynamic_rules=True,
        geo_ip_handler=MagicMock(spec=GeoIPHandler),
    )
    manager = DynamicRuleManager(config)
    base = manager._snapshot_config()
    plans = [manager._build_plan(_rules(index), base) for index in (1, 2)]
    allowed = [_signature(plan.state) for plan in plans]
    allowed.append(_signature(config.__dict__))

    stop = threading.Event()
    mixed: list[dict[str, Any]] = []
    observed = [0]

    def reader() -> None:
        while not stop.is_set():
            snapshot = dict(config.__dict__)
            observed[0] += 1
            if _signature(snapshot) not in allowed:
                mixed.append({name: snapshot[name] for name in FIELDS})

    previous = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    threads = [threading.Thread(target=reader) for _ in range(4)]
    try:
        for thread in threads:
            thread.start()
        for swap in range(SWAPS):
            manager._swap_config(plans[swap % 2])
    finally:
        stop.set()
        for thread in threads:
            thread.join()
        sys.setswitchinterval(previous)
        DynamicRuleManager._instance = None

    assert observed[0] > 0
    assert mixed == []
    assert _signature(config.__dict__) in allowed


def test_the_plan_emits_the_country_warning_not_the_swap() -> None:
    import warnings

    DynamicRuleManager._instance = None
    config = SecurityConfig(
        enable_redis=False,
        enable_agent=True,
        agent_api_key="test-api-key",
        enable_dynamic_rules=True,
        geo_ip_handler=MagicMock(spec=GeoIPHandler),
    )
    manager = DynamicRuleManager(config)
    rules = _rules(1, whitelist_countries=["US"])
    with warnings.catch_warnings(record=True) as during_plan:
        warnings.simplefilter("always")
        plan = manager._build_plan(rules, manager._snapshot_config())
    assert any("blocked_countries is ignored" in str(w.message) for w in during_plan)

    with warnings.catch_warnings(record=True) as during_swap:
        warnings.simplefilter("always")
        manager._swap_config(plan)
    assert during_swap == []
    DynamicRuleManager._instance = None
