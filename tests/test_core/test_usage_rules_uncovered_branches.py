import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core.core.behavioral.context import BehavioralContext
from guard_core.core.behavioral.processor import BehavioralProcessor
from guard_core.core.checks._usage_rules_step import UsageRulesStepCheck
from guard_core.models import SecurityConfig

_IP = "203.0.113.77"


def _processor(config: SecurityConfig) -> BehavioralProcessor:
    context = BehavioralContext(
        config=config,
        logger=logging.getLogger("test_usage_rules_uncovered_branches"),
        event_bus=MagicMock(),
        guard_decorator=None,
        middleware=MagicMock(suspicious_request_counts={}),
    )
    return BehavioralProcessor(context)


def _request() -> MagicMock:
    return MagicMock(
        method="POST",
        headers={},
        url_path="/api/reports",
        client_host=_IP,
        state=SimpleNamespace(),
    )


@pytest.mark.asyncio
async def test_unenforced_trip_without_passive_mode_fires_no_on_block() -> None:
    on_block = AsyncMock()
    config = SecurityConfig(passive_mode=False, on_block=on_block)
    processor = _processor(config)

    with patch(
        "guard_core.core.behavioral._throttle.fire_block_hook", new=AsyncMock()
    ) as fire:
        await processor._fire_throttle_block_hook(_request(), [], False)

    fire.assert_not_awaited()
    on_block.assert_not_awaited()


@pytest.mark.asyncio
async def test_evaluate_usage_rules_error_propagates_without_on_error() -> None:
    processor = _processor(SecurityConfig())
    boom = RuntimeError("tracker lookup failed")

    with patch.object(processor, "_behavior_tracker", side_effect=boom):
        with pytest.raises(RuntimeError, match="tracker lookup failed"):
            await processor.evaluate_usage_rules(
                _request(), SimpleNamespace(), _IP, None, MagicMock()
            )


@pytest.mark.asyncio
async def test_usage_rules_step_check_returns_none() -> None:
    step = UsageRulesStepCheck(MagicMock())

    assert step.check_name == "behavior_usage_rules"
    assert await step.check(_request()) is None
