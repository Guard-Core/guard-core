import logging
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from guard_core.core.initialization import _ban_threshold_report
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.models import DynamicRules, SecurityConfig


def test_a_rule_change_before_any_report_logs_nothing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(enable_redis=False, rate_limit=1)

    with caplog.at_level(logging.WARNING):
        _ban_threshold_report.log_unreachable_ban_thresholds_after_rule_change(
            config, logging.getLogger("test")
        )

    assert caplog.records == []


async def test_a_failing_threshold_check_after_a_rule_is_logged_not_raised(
    caplog: pytest.LogCaptureFixture,
) -> None:
    DynamicRuleManager._instance = None
    config = SecurityConfig(enable_redis=False, rate_limit=100)
    manager = DynamicRuleManager(config)
    rules = DynamicRules(
        rule_id="lower",
        version=1,
        timestamp=datetime.now(timezone.utc),
        global_rate_limit=2,
        global_rate_window=60,
    )
    try:
        with (
            patch(
                "guard_core.core.initialization._ban_threshold_report."
                "log_unreachable_ban_thresholds_after_rule_change",
                side_effect=RuntimeError("boom"),
            ),
            caplog.at_level(logging.ERROR),
        ):
            await manager._apply_rules(rules)
    finally:
        DynamicRuleManager._instance = None

    assert "Checking the ban thresholds after a rule failed" in caplog.text
    assert config.rate_limit == 2
