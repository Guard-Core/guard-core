import json
import time

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sus_patterns.test_detect_penetration_attempt_benchmark import (
    _host_cpu_speed_factor,
)
from tests.test_sync.conftest import SyncMockGuardRequest

_SQLI_PAYLOAD = "' OR 1=1--"
_DEPTH_400_CPU_BUDGET_SECONDS = 0.6


def _nested_json_body(depth: int, leaf: str) -> bytes:
    leaf_json = json.dumps(leaf)
    prefix = '{"a":' * depth
    suffix = "}" * depth
    return (prefix + leaf_json + suffix).encode()


def _json_request(body: bytes) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(
        method="POST",
        body_content=body,
        headers={
            "content-type": "application/json",
            "content-length": str(len(body)),
        },
    )


@pytest.mark.redos_timing
def test_depth_400_json_body_scan_stays_cpu_bounded() -> None:
    config = SyncSecurityConfig()
    sus_patterns_handler.configure(config)
    assert sus_patterns_handler._detection_state.compiler is not None
    request = _json_request(_nested_json_body(400, _SQLI_PAYLOAD))

    detect_penetration_attempt(request, config)

    samples: list[float] = []
    for _ in range(5):
        start = time.process_time()
        detect_penetration_attempt(request, config)
        samples.append(time.process_time() - start)

    budget_seconds = _DEPTH_400_CPU_BUDGET_SECONDS * _host_cpu_speed_factor()
    assert min(samples) < budget_seconds, (
        "depth-400 nested JSON body scan regressed: min of 5 runs took "
        f"{min(samples):.4f}s, budget={budget_seconds:.4f}s (base "
        f"{_DEPTH_400_CPU_BUDGET_SECONDS}s scaled by this host's "
        "_host_cpu_speed_factor()). The unbounded recursive walk this "
        "replaces raised RecursionError around depth 325 after burning "
        "several CPU seconds; the depth cap keeps this bounded regardless "
        "of body depth."
    )
