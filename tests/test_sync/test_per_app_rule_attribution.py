from collections.abc import Iterator
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.models import DynamicRules, SyncSecurityConfig
from guard_core.sync._utils import rule_attribution
from guard_core.sync.core.checks.factory import build_default_pipeline
from guard_core.sync.decorators import SecurityDecorator
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from tests.test_sync.conftest import SyncMockGuardRequest
from tests.test_sync.test_core.conftest import build_middleware

RULE_ID = "RULE-OF-APP-A"
DYNAMIC = {"matched_rule_type": "dynamic", "matched_rule_id": RULE_ID}
DYNAMIC_OVERLAP = {**DYNAMIC, "matched_rule_overlaps_static": True}


@pytest.fixture(autouse=True)
def reset_singleton() -> Iterator[None]:
    DynamicRuleManager._instance = None
    yield
    DynamicRuleManager._instance = None


def _config(**overrides: Any) -> SyncSecurityConfig:
    fields: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
        "lazy_init": False,
        "enable_dynamic_rules": False,
    }
    fields.update(overrides)
    return SyncSecurityConfig(**fields)


def _apply_user_agent_rule(config: SyncSecurityConfig) -> DynamicRuleManager:
    manager = DynamicRuleManager(config)
    agent = MagicMock()
    agent.send_event = MagicMock()
    agent.get_dynamic_rules = MagicMock(
        return_value=DynamicRules(
            rule_id=RULE_ID,
            version=1,
            timestamp=datetime.now(timezone.utc),
            blocked_user_agents=["wp23bot"],
        )
    )
    manager.agent_handler = agent
    manager.update_rules()
    assert manager.current_rules is not None
    return manager


def _user_agent_event_attribution(config: SyncSecurityConfig) -> dict[str, Any]:
    middleware = build_middleware(config, SecurityDecorator(config), None)
    request = SyncMockGuardRequest(
        path="/x", client_host="198.51.100.5", headers={"User-Agent": "wp23bot"}
    )
    build_default_pipeline(middleware).execute(request)
    calls = middleware.event_bus.send_middleware_event.call_args_list
    [event] = [
        call.kwargs
        for call in calls
        if call.kwargs["event_type"] == "user_agent_blocked"
    ]
    return {key: value for key, value in event.items() if key.startswith("matched_")}


def test_an_app_never_carries_the_rule_set_another_app_applied() -> None:
    app_a = _config(enable_agent=True, agent_api_key="key", enable_dynamic_rules=True)
    app_b = _config(blocked_user_agents=["wp23bot"])
    assert _user_agent_event_attribution(app_b) == {}

    _apply_user_agent_rule(app_a)

    assert _user_agent_event_attribution(app_b) == {}


def test_each_app_carries_only_the_rule_set_it_applied() -> None:
    app_a = _config(
        enable_agent=True,
        agent_api_key="key",
        enable_dynamic_rules=True,
        blocked_user_agents=["wp23bot"],
    )
    app_b = _config(
        enable_agent=True,
        agent_api_key="key",
        enable_dynamic_rules=True,
        blocked_user_agents=["wp23bot"],
    )
    manager_a = _apply_user_agent_rule(app_a)
    assert _user_agent_event_attribution(app_a) == DYNAMIC_OVERLAP
    manager_b = DynamicRuleManager(app_b)
    assert manager_b is not manager_a

    assert _user_agent_event_attribution(app_b) == {}

    manager_a.current_rules = None
    manager_a._refresh_attribution()
    assert _user_agent_event_attribution(app_a) == {}


def test_set_attribution_view_clears_the_view_of_the_default_manager() -> None:
    app = _config(enable_agent=True, agent_api_key="key", enable_dynamic_rules=True)
    manager = _apply_user_agent_rule(app)
    assert manager._attribution_view is not None

    rule_attribution.set_attribution_view(None)

    assert rule_attribution._view_of(app) is None
    assert rule_attribution.emergency_attribution(app) == {}


def test_set_attribution_view_sets_the_view_of_the_app_it_is_given() -> None:
    app = _config(enable_agent=True, agent_api_key="key", enable_dynamic_rules=True)
    manager = _apply_user_agent_rule(app)
    view = manager._attribution_view
    assert view is not None
    other = _config()

    rule_attribution.set_attribution_view(None, app)
    assert rule_attribution._view_of(app) is None
    rule_attribution.set_attribution_view(view, app)
    assert rule_attribution._view_of(app) is view
    rule_attribution.set_attribution_view(view, other)
    assert rule_attribution._view_of(other) is None
