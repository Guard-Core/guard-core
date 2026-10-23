import threading
from unittest.mock import Mock

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
    middleware.config = Mock()
    middleware.logger = Mock()
    return middleware


def test_concurrent_rebuild_self_heals_a_lost_check() -> None:
    config = SyncSecurityConfig(
        enable_penetration_detection=False, enable_rate_limiting=False
    )
    middleware = _stub_middleware()
    baseline_check = _StubCheck(middleware, "route_config")
    cloud_check = _StubCheck(middleware, "cloud_provider")

    build_started = threading.Event()
    release_slow_build = threading.Event()
    call_count = 0
    call_count_lock = threading.Lock()

    def rebuild_checks() -> list[SecurityCheck]:
        nonlocal call_count
        with call_count_lock:
            call_count += 1
            is_first_call = call_count == 1
        if is_first_call:
            build_started.set()
            assert release_slow_build.wait(timeout=5)
            return [baseline_check]
        return [baseline_check, cloud_check]

    pipeline = SecurityCheckPipeline(
        [baseline_check],
        config=config,
        rebuild_checks=rebuild_checks,
        watched_container_fields=("block_cloud_providers",),
    )

    config.custom_log_file = "trigger-first-staleness.log"

    slow_thread = threading.Thread(target=pipeline._rebuild_if_stale)
    slow_thread.start()
    assert build_started.wait(timeout=5)

    config.block_cloud_providers = frozenset({"AWS"})

    fast_thread = threading.Thread(target=pipeline._rebuild_if_stale)
    fast_thread.start()
    fast_thread.join(timeout=5)

    release_slow_build.set()
    slow_thread.join(timeout=5)

    missing_after_race = "cloud_provider" not in pipeline.get_check_names()
    believes_current_after_race = pipeline._built_revision == config.revision
    assert not (missing_after_race and believes_current_after_race)

    pipeline._rebuild_if_stale()

    assert "cloud_provider" in pipeline.get_check_names()
    assert pipeline._built_revision == config.revision
