import concurrent.futures
import json
import re
import time

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import (
    DetectionResult,
    SusPatternsManager,
    sus_patterns_handler,
)
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_CONFIG = SyncSecurityConfig()

_REDOS_PAYLOAD = "{{" * 10000
_BENIGN_MATCHING_PAYLOAD = "<script>alert(1)</script>"
_CONCURRENCY = 4
_DEADLINE_SECONDS = 30.0
_CUSTOM_MARKER = "zzq_custom_hardening_marker_zzq"
_CUSTOM_PATTERN = rf"{_CUSTOM_MARKER}\d+"


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())
    sus_patterns_handler.compiled_custom_patterns = set()
    sus_patterns_handler.custom_patterns = set()


def _json_body_request(payload: str) -> SyncMockGuardRequest:
    body = json.dumps({"outer": {"field": payload}}).encode()
    headers = {
        "content-length": str(len(body)),
        "content-type": "application/json",
    }
    return SyncMockGuardRequest(body_content=body, headers=headers)


def _raw_body_request(payload: str) -> SyncMockGuardRequest:
    body = payload.encode()
    headers = {"content-length": str(len(body))}
    return SyncMockGuardRequest(body_content=body, headers=headers)


@pytest.mark.redos_timing
def test_no_false_negative_under_concurrent_redos_sync() -> None:
    redos_request = _raw_body_request(_REDOS_PAYLOAD)
    benign_request = _raw_body_request(_BENIGN_MATCHING_PAYLOAD)

    def _detect(req: SyncMockGuardRequest) -> bool:
        result = detect_penetration_attempt(req, _CONFIG)
        return result.is_threat

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=_CONCURRENCY + 1
    ) as executor:
        futures = []
        for _ in range(_CONCURRENCY):
            futures.append(executor.submit(_detect, redos_request))
        futures.append(executor.submit(_detect, benign_request))

        start = time.monotonic()
        results = [f.result(timeout=_DEADLINE_SECONDS) for f in futures]
        elapsed = time.monotonic() - start

    assert results[-1], (
        f"Benign matching payload was not detected under concurrent ReDoS load "
        f"(false negative). Elapsed: {elapsed:.2f}s"
    )
    assert elapsed < _DEADLINE_SECONDS, (
        f"Concurrent detect calls hung. Elapsed: {elapsed:.2f}s"
    )


@pytest.mark.redos_timing
def test_concurrent_custom_and_benign_no_false_negative_sync() -> None:
    SusPatternsManager.add_pattern(_CUSTOM_PATTERN, custom=True)
    custom_payload = f"{_CUSTOM_MARKER}99"
    benign_payload = _BENIGN_MATCHING_PAYLOAD

    def _custom_detect() -> DetectionResult:
        return sus_patterns_handler.detect(custom_payload, "1.2.3.4", "request_body")

    def _benign_detect() -> DetectionResult:
        return sus_patterns_handler.detect(benign_payload, "5.6.7.8", "request_body")

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(_custom_detect) for _ in range(4)]
        futures.append(executor.submit(_benign_detect))

        start = time.monotonic()
        results = [f.result(timeout=15.0) for f in futures]
        elapsed = time.monotonic() - start

    benign_result = results[-1]
    assert benign_result["is_threat"] is True, (
        f"benign payload was not detected under concurrent custom load: "
        f"elapsed={elapsed:.2f}s"
    )
    assert elapsed < 15.0


@pytest.mark.redos_timing
def test_slipping_custom_pattern_detect_completes_sync() -> None:
    slipping = re.compile(r"(\w|\w)*x")
    compiled_tuple = (slipping, frozenset({"request_body", "unknown"}), "custom")
    sus_patterns_handler.compiled_custom_patterns.add(compiled_tuple)

    payload = "a" * 22

    start = time.monotonic()
    result = sus_patterns_handler.detect(payload, "1.2.3.4", "request_body")
    elapsed = time.monotonic() - start

    assert isinstance(result, dict)
    assert "is_threat" in result
    assert elapsed < 10.0
