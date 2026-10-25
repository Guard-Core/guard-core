import json
import random
import time
from collections.abc import Iterator

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import (
    SusPatternsManager,
    sus_patterns_handler,
    sus_patterns_manager_for,
)
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sus_patterns.test_detect_penetration_attempt_benchmark import (
    _host_cpu_speed_factor,
)
from tests.test_sync.conftest import SyncMockGuardRequest

_TWENTY_EIGHT_VALUES_CPU_BUDGET_SECONDS = 1.0


def _reset_singleton_to_legacy() -> None:
    sus_patterns_handler._compiler = None
    sus_patterns_handler._preprocessor = None
    sus_patterns_handler._semantic_analyzer = None
    sus_patterns_handler._performance_monitor = None
    sus_patterns_handler._threat_score_threshold = 1.0
    SusPatternsManager._config = None


def _twenty_eight_large_values_request() -> SyncMockGuardRequest:
    rng = random.Random(7)
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    payload = {
        f"k{i}": "".join(rng.choice(alphabet) for _ in range(9342)) for i in range(28)
    }
    body = json.dumps(payload).encode()
    return SyncMockGuardRequest(
        method="POST",
        body_content=body,
        headers={
            "content-type": "application/json",
            "content-length": str(len(body)),
        },
    )


@pytest.fixture(autouse=True)
def _restore_singleton_after_test() -> Iterator[None]:
    yield
    sus_patterns_handler.configure(SyncSecurityConfig())


def test_fresh_unconfigured_singleton_auto_configures_on_bare_call() -> None:
    _reset_singleton_to_legacy()
    assert sus_patterns_handler._detection_state.compiler is None

    config = SyncSecurityConfig()
    request = SyncMockGuardRequest(query_params={"q": "hello"})

    detect_penetration_attempt(request, config)

    assert sus_patterns_handler._detection_state.compiler is not None


@pytest.mark.redos_timing
def test_fresh_unconfigured_singleton_runs_enhanced_within_the_ceiling() -> None:
    _reset_singleton_to_legacy()
    config = SyncSecurityConfig()
    request = _twenty_eight_large_values_request()

    detect_penetration_attempt(request, config)
    assert sus_patterns_handler._detection_state.compiler is not None

    samples: list[float] = []
    for _ in range(5):
        start = time.process_time()
        detect_penetration_attempt(request, config)
        samples.append(time.process_time() - start)

    budget_seconds = _TWENTY_EIGHT_VALUES_CPU_BUDGET_SECONDS * _host_cpu_speed_factor()
    assert min(samples) < budget_seconds, (
        "a bare detect_penetration_attempt(request, config) call on an "
        "unconfigured singleton must auto-configure into enhanced mode; min "
        f"of 5 runs took {min(samples):.4f}s, budget={budget_seconds:.4f}s. "
        "Legacy mode measures this same body an order of magnitude slower "
        "via the per-pattern thread-pool dispatch."
    )


def test_second_call_with_the_same_config_object_does_not_reconfigure() -> None:
    _reset_singleton_to_legacy()
    config = SyncSecurityConfig()
    request = SyncMockGuardRequest(query_params={"q": "hello"})

    detect_penetration_attempt(request, config)
    state_after_first_call = sus_patterns_handler._detection_state

    detect_penetration_attempt(request, config)
    state_after_second_call = sus_patterns_handler._detection_state

    assert state_after_second_call is state_after_first_call


def test_call_with_a_different_config_object_reconfigures() -> None:
    _reset_singleton_to_legacy()
    config_a = SyncSecurityConfig()
    request = SyncMockGuardRequest(query_params={"q": "hello"})

    detect_penetration_attempt(request, config_a)
    manager_a = sus_patterns_manager_for(config_a)
    state_after_config_a = manager_a._detection_state

    config_b = SyncSecurityConfig()
    detect_penetration_attempt(request, config_b)
    manager_b = sus_patterns_manager_for(config_b)

    assert manager_b is not manager_a
    assert manager_b._detection_state is not state_after_config_a
    assert manager_b._config is config_b
    assert manager_a._detection_state is state_after_config_a
    assert manager_a._config is config_a
