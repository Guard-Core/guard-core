import logging
from collections.abc import Iterator
from datetime import datetime, timezone

import pytest

from guard_core.models import DynamicRules, SyncSecurityConfig
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_manager_for

USER_AGENT_PATTERN = r"acmehouse_bot_[0-9]{3}"
REDOS_PATTERN = r"(acmehouse_a+)+$"


@pytest.fixture(autouse=True)
def reset_singleton() -> Iterator[None]:
    DynamicRuleManager._instance = None
    yield
    DynamicRuleManager._instance = None


def _app(**settings: object) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=False,
        enable_dynamic_rules=False,
        lazy_init=False,
        **settings,
    )


def _two_apps() -> tuple[SyncSecurityConfig, SyncSecurityConfig]:
    sus_patterns_manager_for(_app(), bind=True)
    app_a = _app()
    app_b = _app(log_sensitive_params=frozenset({"acmehouse"}))
    sus_patterns_manager_for(app_a, bind=True)
    sus_patterns_manager_for(app_b, bind=True)
    return app_a, app_b


def _plan_messages(config: SyncSecurityConfig) -> str:
    manager = DynamicRuleManager(config)
    rules = DynamicRules(
        rule_id="R",
        version=1,
        timestamp=datetime.now(timezone.utc),
        blocked_user_agents=[USER_AGENT_PATTERN],
    )
    plan = manager._build_plan(rules, manager._snapshot_config())
    return " ".join(message for _, message in plan.messages)


def test_the_plan_log_redacts_the_names_of_the_app_it_belongs_to() -> None:
    app_a, app_b = _two_apps()

    text_a = _plan_messages(app_a)
    DynamicRuleManager._instance = None
    text_b = _plan_messages(app_b)

    assert USER_AGENT_PATTERN in text_a
    assert USER_AGENT_PATTERN not in text_b
    assert "[REDACTED]" in text_b


def test_the_rejected_pattern_log_redacts_the_names_of_the_app_it_belongs_to(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app_a, app_b = _two_apps()

    with caplog.at_level(logging.INFO):
        DynamicRuleManager(app_a)._apply_pattern_rules([REDOS_PATTERN])
        text_a = caplog.text
        caplog.clear()
        DynamicRuleManager._instance = None
        DynamicRuleManager(app_b)._apply_pattern_rules([REDOS_PATTERN])
        text_b = caplog.text

    assert REDOS_PATTERN in text_a
    assert REDOS_PATTERN not in text_b
    assert "[REDACTED]" in text_b
