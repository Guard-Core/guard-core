from typing import cast
from unittest.mock import Mock

from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.checks.base import SecurityCheck
from guard_core.sync.core.checks.factory import DEFAULT_CHECK_CLASSES
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


class _EnforcedCheck(SecurityCheck):
    enforced_on_excluded_paths = True

    @property
    def check_name(self) -> str:
        return "enforced_check"

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        return cast(GuardResponse, Mock(status_code=403))


class _SkippedCheck(SecurityCheck):
    @property
    def check_name(self) -> str:
        return "skipped_check"

    def check(self, request: SyncGuardRequest) -> GuardResponse | None:
        return cast(GuardResponse, Mock(status_code=403))


def _mock_middleware() -> Mock:
    middleware = Mock()
    middleware.config = Mock()
    middleware.config.fail_secure = False
    middleware.config.passive_mode = False
    middleware.config.on_block = None
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    return middleware


def _excluded_request() -> Mock:
    request = Mock()
    request.url_path = "/healthz"
    request.method = "GET"
    request.state = type("S", (), {})()
    request.state.guard_exclusion_scoped = True
    return request


def test_security_check_defaults_to_not_enforced_on_excluded_paths() -> None:
    assert SecurityCheck.enforced_on_excluded_paths is False


def test_pipeline_skips_a_check_whose_flag_is_false_on_an_excluded_request() -> None:
    middleware = _mock_middleware()
    pipeline = SecurityCheckPipeline([_SkippedCheck(middleware)])

    result = pipeline.execute(_excluded_request())

    assert result is None


def test_pipeline_runs_a_check_whose_flag_is_true_on_an_excluded_request() -> None:
    middleware = _mock_middleware()
    pipeline = SecurityCheckPipeline([_EnforcedCheck(middleware)])

    result = pipeline.execute(_excluded_request())

    assert result is not None
    assert result.status_code == 403


def test_pipeline_runs_check_on_non_excluded_request_regardless_of_flag() -> None:
    middleware = _mock_middleware()
    pipeline = SecurityCheckPipeline([_SkippedCheck(middleware)])
    request = Mock()
    request.url_path = "/other"
    request.method = "GET"
    request.state = type("S", (), {})()

    result = pipeline.execute(request)

    assert result is not None
    assert result.status_code == 403


def test_default_check_classes_enforced_on_excluded_paths_is_exactly_three() -> None:
    middleware = _mock_middleware()
    checks = [cls(middleware) for cls in DEFAULT_CHECK_CLASSES]

    enforced_names = {
        check.check_name for check in checks if check.enforced_on_excluded_paths
    }

    assert enforced_names == {"route_config", "ip_security", "emergency_mode"}
