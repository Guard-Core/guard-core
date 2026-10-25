from unittest.mock import MagicMock

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_manager_for

_PATTERN = r"dynonlyA_[a-z]{3,6}"


def _bound_app() -> tuple[SyncSecurityConfig, MagicMock]:
    config = SyncSecurityConfig()
    agent = MagicMock()
    sus_patterns_manager_for(config, bind=True).agent_handler = agent
    return config, agent


def _event_types(agent: MagicMock) -> list[str]:
    return [call.args[0].event_type for call in agent.send_event.call_args_list]


def test_a_dynamic_pattern_of_one_app_never_reaches_the_next_app() -> None:
    config_a, agent_a = _bound_app()
    config_b, agent_b = _bound_app()
    config_c, agent_c = _bound_app()
    managers = [sus_patterns_manager_for(c) for c in (config_a, config_b, config_c)]
    assert len({id(m.patterns) for m in managers}) == 3

    rules = DynamicRuleManager(config_a)
    created: list[str] = []
    rules._apply_pattern_rules([_PATTERN], created)

    assert created == [_PATTERN]
    assert _PATTERN in sus_patterns_manager_for(config_a).patterns
    assert _PATTERN not in sus_patterns_manager_for(config_b).patterns
    assert _PATTERN not in sus_patterns_manager_for(config_c).patterns
    assert "pattern_added" in _event_types(agent_a)
    assert agent_b.send_event.call_count == 0
    assert agent_c.send_event.call_count == 0

    config_d, agent_d = _bound_app()
    assert _PATTERN not in sus_patterns_manager_for(config_d).patterns
    DynamicRuleManager(config_d)._revoke_owned([], created)
    assert agent_d.send_event.call_count == 0
    assert _PATTERN in sus_patterns_manager_for(config_a).patterns

    rules._revoke_owned([], created)
    assert _PATTERN not in sus_patterns_manager_for(config_a).patterns
    assert _event_types(agent_a).count("pattern_removed") == 1
    assert agent_b.send_event.call_count == agent_c.send_event.call_count == 0
