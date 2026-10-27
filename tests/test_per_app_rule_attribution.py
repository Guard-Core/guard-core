from collections.abc import Iterator
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core._utils import rule_attribution
from guard_core.core.checks.factory import build_default_pipeline
from guard_core.decorators import SecurityDecorator
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.models import DynamicRules, SecurityConfig
from tests.conftest import MockGuardRequest
from tests.test_core.conftest import build_middleware

RULE_ID = "RULE-OF-APP-A"
DYNAMIC = {"matched_rule_type": "dynamic", "matched_rule_id": RULE_ID}
DYNAMIC_OVERLAP = {**DYNAMIC, "matched_rule_overlaps_static": True}


@pytest.fixture(autouse=True)
def reset_singleton() -> Iterator[None]:
    DynamicRuleManager._instance = None
    yield
    DynamicRuleManager._instance = None


def _config(**overrides: Any) -> SecurityConfig:
    fields: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
        "lazy_init": False,
        "enable_dynamic_rules": False,
    }
    fields.update(overrides)
    return SecurityConfig(**fields)


async def _apply_user_agent_rule(config: SecurityConfig) -> DynamicRuleManager:
    manager = DynamicRuleManager(config)
    agent = MagicMock()
    agent.send_event = AsyncMock()
    agent.get_dynamic_rules = AsyncMock(
        return_value=DynamicRules(
            rule_id=RULE_ID,
            version=1,
            timestamp=datetime.now(timezone.utc),
            blocked_user_agents=["wp23bot"],
        )
    )
    manager.agent_handler = agent
    await manager.update_rules()
    assert manager.current_rules is not None
    return manager


async def _user_agent_event_attribution(config: SecurityConfig) -> dict[str, Any]:
    middleware = build_middleware(config, SecurityDecorator(config), None)
    request = MockGuardRequest(
        path="/x", client_host="198.51.100.5", headers={"User-Agent": "wp23bot"}
    )
    await build_default_pipeline(middleware).execute(request)
    calls = middleware.event_bus.send_middleware_event.call_args_list
    [event] = [
        call.kwargs
        for call in calls
        if call.kwargs["event_type"] == "user_agent_blocked"
    ]
    return {key: value for key, value in event.items() if key.startswith("matched_")}


async def test_an_app_never_carries_the_rule_set_another_app_applied() -> None:
    app_a = _config(enable_agent=True, agent_api_key="key", enable_dynamic_rules=True)
    app_b = _config(blocked_user_agents=["wp23bot"])
    assert await _user_agent_event_attribution(app_b) == {}

    await _apply_user_agent_rule(app_a)

    assert await _user_agent_event_attribution(app_b) == {}


async def test_each_app_carries_only_the_rule_set_it_applied() -> None:
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
    manager_a = await _apply_user_agent_rule(app_a)
    assert await _user_agent_event_attribution(app_a) == DYNAMIC_OVERLAP
    manager_b = DynamicRuleManager(app_b)
    assert manager_b is not manager_a

    assert await _user_agent_event_attribution(app_b) == {}

    manager_a.current_rules = None
    manager_a._refresh_attribution()
    assert await _user_agent_event_attribution(app_a) == {}


async def test_set_attribution_view_clears_the_view_of_the_default_manager() -> None:
    app = _config(enable_agent=True, agent_api_key="key", enable_dynamic_rules=True)
    manager = await _apply_user_agent_rule(app)
    assert manager._attribution_view is not None

    rule_attribution.set_attribution_view(None)

    assert rule_attribution._view_of(app) is None
    assert rule_attribution.emergency_attribution(app) == {}


async def test_set_attribution_view_sets_the_view_of_the_app_it_is_given() -> None:
    app = _config(enable_agent=True, agent_api_key="key", enable_dynamic_rules=True)
    manager = await _apply_user_agent_rule(app)
    view = manager._attribution_view
    assert view is not None
    other = _config()

    rule_attribution.set_attribution_view(None, app)
    assert rule_attribution._view_of(app) is None
    rule_attribution.set_attribution_view(view, app)
    assert rule_attribution._view_of(app) is view
    rule_attribution.set_attribution_view(view, other)
    assert rule_attribution._view_of(other) is None
