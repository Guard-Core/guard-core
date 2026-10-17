from unittest.mock import AsyncMock, MagicMock

from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest


def _failing_check(config: SecurityConfig) -> MagicMock:
    check = MagicMock()
    check.check_name = "boom"
    check.config = config
    check.check = AsyncMock(side_effect=RuntimeError("boom"))
    check.create_error_response = AsyncMock(return_value="BLOCKED")
    return check


def _pipeline(
    config: SecurityConfig, logger: MagicMock
) -> tuple[SecurityCheckPipeline, MagicMock]:
    check = _failing_check(config)
    pipeline = SecurityCheckPipeline([check])
    pipeline.logger = logger
    return pipeline, check


async def test_passive_mode_logs_the_check_error_and_lets_the_request_continue() -> (
    None
):
    config = SecurityConfig(enable_redis=False, passive_mode=True, fail_secure=True)
    logger = MagicMock()
    pipeline, check = _pipeline(config, logger)

    result = await pipeline.execute(MockGuardRequest(path="/x"))

    assert result is None
    logged = " ".join(str(call.args[0]) for call in logger.error.call_args_list)
    assert "Error in security check boom" in logged
    check.create_error_response.assert_not_called()


async def test_active_mode_still_blocks_on_a_check_error() -> None:
    config = SecurityConfig(enable_redis=False, passive_mode=False, fail_secure=True)
    pipeline, _ = _pipeline(config, MagicMock())

    result = await pipeline.execute(MockGuardRequest(path="/x"))

    assert result == "BLOCKED"


async def test_passive_mode_check_error_is_not_logged_when_the_check_is_muted() -> None:
    config = SecurityConfig(enable_redis=False, passive_mode=True, fail_secure=True)
    logger = MagicMock()
    pipeline, _ = _pipeline(config, logger)
    pipeline.muted_check_logs = frozenset({"boom"})

    result = await pipeline.execute(MockGuardRequest(path="/x"))

    assert result is None
    logger.error.assert_not_called()
