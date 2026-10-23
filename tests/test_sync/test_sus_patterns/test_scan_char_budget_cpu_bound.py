import json
import random
import time

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sus_patterns.test_detect_penetration_attempt_benchmark import (
    _host_cpu_speed_factor,
)
from tests.test_sync.conftest import SyncMockGuardRequest

_ALPHANUMERIC = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_TWENTY_EIGHT_VALUES_CPU_BUDGET_SECONDS = 1.0
_FIVE_TWELVE_VALUES_CPU_BUDGET_SECONDS = 2.8


def _random_alphanumeric(rng: random.Random, length: int) -> str:
    return "".join(rng.choice(_ALPHANUMERIC) for _ in range(length))


def _json_body_request(payload: dict[str, str]) -> SyncMockGuardRequest:
    body = json.dumps(payload).encode()
    return SyncMockGuardRequest(
        method="POST",
        body_content=body,
        headers={
            "content-type": "application/json",
            "content-length": str(len(body)),
        },
    )


def _assert_enhanced_mode(config: SyncSecurityConfig) -> None:
    sus_patterns_handler.configure(config)
    assert sus_patterns_handler._detection_state.compiler is not None, (
        "CPU ceiling tests must measure the enhanced-detection path; an "
        "unconfigured singleton falls back to legacy mode, whose per-pattern "
        "thread-pool dispatch is an order of magnitude slower and would make "
        "this ceiling meaningless."
    )


@pytest.mark.redos_timing
def test_twenty_eight_large_values_body_scan_stays_cpu_bounded() -> None:
    config = SyncSecurityConfig()
    _assert_enhanced_mode(config)

    rng = random.Random(7)
    payload = {f"k{i}": _random_alphanumeric(rng, 9342) for i in range(28)}
    request = _json_body_request(payload)

    detect_penetration_attempt(request, config)

    samples: list[float] = []
    for _ in range(5):
        start = time.process_time()
        detect_penetration_attempt(request, config)
        samples.append(time.process_time() - start)

    budget_seconds = _TWENTY_EIGHT_VALUES_CPU_BUDGET_SECONDS * _host_cpu_speed_factor()
    assert min(samples) < budget_seconds, (
        "28 x 9342-char body scan regressed: min of 5 runs took "
        f"{min(samples):.4f}s, budget={budget_seconds:.4f}s (base "
        f"{_TWENTY_EIGHT_VALUES_CPU_BUDGET_SECONDS}s scaled by this host's "
        "_host_cpu_speed_factor()). This shape cost 1.81s CPU in enhanced "
        "mode before detection_max_scan_chars and the monitor.py "
        "statistics.mean cut; either regressing alone reopens that cost."
    )


@pytest.mark.redos_timing
def test_five_hundred_twelve_small_values_body_scan_stays_cpu_bounded() -> None:
    config = SyncSecurityConfig()
    _assert_enhanced_mode(config)

    rng = random.Random(11)
    payload = {f"k{i}": _random_alphanumeric(rng, 30) for i in range(512)}
    request = _json_body_request(payload)

    detect_penetration_attempt(request, config)

    samples: list[float] = []
    for _ in range(5):
        start = time.process_time()
        detect_penetration_attempt(request, config)
        samples.append(time.process_time() - start)

    budget_seconds = _FIVE_TWELVE_VALUES_CPU_BUDGET_SECONDS * _host_cpu_speed_factor()
    assert min(samples) < budget_seconds, (
        "512 x 30-byte body scan regressed: min of 5 runs took "
        f"{min(samples):.4f}s, budget={budget_seconds:.4f}s (base "
        f"{_FIVE_TWELVE_VALUES_CPU_BUDGET_SECONDS}s scaled by this host's "
        "_host_cpu_speed_factor()). This shape plateaus at "
        "detection_max_scan_values (512) without ever reaching "
        "detection_max_scan_chars, so it isolates the constant-factor cuts "
        "from the char budget; it measured 1.4s CPU after those cuts (this "
        "ceiling is 2x that), down from 4.0 to 5.3s CPU before them."
    )
