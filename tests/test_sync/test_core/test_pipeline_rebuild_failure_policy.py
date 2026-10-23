from unittest.mock import MagicMock, Mock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


class _StubCheck(SecurityCheck):
    def __init__(self, middleware: Mock, name: str) -> None:
        super().__init__(middleware)
        self._name = name

    @property
    def check_name(self) -> str:
        return self._name

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        return None


def _stub_middleware() -> Mock:
    middleware = Mock()
    middleware.logger = Mock()
    middleware.create_error_response = MagicMock(return_value=Mock(status_code=500))
    return middleware


def _mock_request() -> Mock:
    request = Mock()
    request.url_path = "/x"
    request.method = "GET"
    request.state = type("S", (), {})()
    return request


def _raising_rebuild() -> list[SecurityCheck]:
    raise RuntimeError("boom")


def test_execute_blocks_when_fail_secure_and_rebuild_raises() -> None:
    config = SyncSecurityConfig(fail_secure=True)
    middleware = _stub_middleware()
    check = _StubCheck(middleware, "route_config")

    pipeline = SecurityCheckPipeline(
        [check], config=config, rebuild_checks=_raising_rebuild
    )
    config.custom_log_file = "trigger-staleness.log"

    result = pipeline.execute(_mock_request())

    assert result is middleware.create_error_response.return_value
    middleware.create_error_response.assert_called_once_with(
        500, "Security check failed"
    )


def test_execute_continues_on_last_known_good_checks_when_not_fail_secure() -> None:
    config = SyncSecurityConfig(fail_secure=False)
    middleware = _stub_middleware()
    check = _StubCheck(middleware, "route_config")

    pipeline = SecurityCheckPipeline(
        [check], config=config, rebuild_checks=_raising_rebuild
    )
    config.custom_log_file = "trigger-staleness.log"

    result = pipeline.execute(_mock_request())

    assert result is None
    middleware.create_error_response.assert_not_called()
    assert pipeline.checks == [check]


def test_transient_rebuild_failure_recovers_on_a_later_request() -> None:
    config = SyncSecurityConfig(fail_secure=False)
    middleware = _stub_middleware()
    old_check = _StubCheck(middleware, "route_config")
    new_check = _StubCheck(middleware, "cloud_provider")

    attempts = {"n": 0}

    def flaky_rebuild() -> list[SecurityCheck]:
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise RuntimeError("boom")
        return [old_check, new_check]

    pipeline = SecurityCheckPipeline(
        [old_check], config=config, rebuild_checks=flaky_rebuild
    )
    config.custom_log_file = "trigger-staleness.log"

    pipeline.execute(_mock_request())
    assert pipeline.get_check_names() == ["route_config"]

    pipeline.execute(_mock_request())
    assert pipeline.get_check_names() == ["route_config", "cloud_provider"]


def test_execute_reraises_when_fail_secure_and_no_known_good_checks_exist() -> None:
    config = SyncSecurityConfig(fail_secure=True)

    pipeline = SecurityCheckPipeline([], config=config, rebuild_checks=_raising_rebuild)
    config.custom_log_file = "trigger-staleness.log"

    with pytest.raises(RuntimeError, match="boom"):
        pipeline.execute(_mock_request())
