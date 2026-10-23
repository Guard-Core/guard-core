from unittest.mock import MagicMock

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
from tests.test_sync.conftest import SyncMockGuardRequest


def _failing_check(config: SyncSecurityConfig) -> MagicMock:
    check = MagicMock()
    check.check_name = "boom"
    check.config = config
    check.check = MagicMock(side_effect=RuntimeError("boom"))
    check.create_error_response = MagicMock(return_value="BLOCKED")
    return check


def _pipeline(
    config: SyncSecurityConfig, logger: MagicMock
) -> tuple[SecurityCheckPipeline, MagicMock]:
    check = _failing_check(config)
    pipeline = SecurityCheckPipeline([check])
    pipeline.logger = logger
    return pipeline, check


def test_passive_mode_logs_the_check_error_and_lets_the_request_continue() -> None:
    config = SyncSecurityConfig(enable_redis=False, passive_mode=True, fail_secure=True)
    logger = MagicMock()
    pipeline, check = _pipeline(config, logger)

    result = pipeline.execute(SyncMockGuardRequest(path="/x"))

    assert result is None
    logged = " ".join(str(call.args[0]) for call in logger.error.call_args_list)
    assert "Error in security check boom" in logged
    check.create_error_response.assert_not_called()


def test_active_mode_still_blocks_on_a_check_error() -> None:
    config = SyncSecurityConfig(
        enable_redis=False, passive_mode=False, fail_secure=True
    )
    pipeline, _ = _pipeline(config, MagicMock())

    result = pipeline.execute(SyncMockGuardRequest(path="/x"))

    assert result == "BLOCKED"


def test_passive_mode_check_error_is_not_logged_when_the_check_is_muted() -> None:
    config = SyncSecurityConfig(enable_redis=False, passive_mode=True, fail_secure=True)
    logger = MagicMock()
    pipeline, _ = _pipeline(config, logger)
    pipeline.muted_check_logs = frozenset({"boom"})

    result = pipeline.execute(SyncMockGuardRequest(path="/x"))

    assert result is None
    logger.error.assert_not_called()
