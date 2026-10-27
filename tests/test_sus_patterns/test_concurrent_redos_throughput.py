import asyncio
import json
import re
import time

import pytest

from guard_core import SecurityConfig
from guard_core.handlers.suspatterns_handler import (
    DetectionResult,
    SusPatternsManager,
    sus_patterns_handler,
)
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

_CONFIG = SecurityConfig()

_REDOS_PAYLOAD = "{{" * 10000
_BENIGN_MATCHING_PAYLOAD = "<script>alert(1)</script>"
_CONCURRENCY = 4
_DEADLINE_SECONDS = 30.0
_CUSTOM_MARKER = "zzq_custom_hardening_marker_zzq"
_CUSTOM_PATTERN = rf"{_CUSTOM_MARKER}\d+"


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())
    sus_patterns_handler.compiled_custom_patterns = set()
    sus_patterns_handler.custom_patterns = set()


def _json_body_request(payload: str) -> MockGuardRequest:
    body = json.dumps({"outer": {"field": payload}}).encode()
    headers = {
        "content-length": str(len(body)),
        "content-type": "application/json",
    }
    return MockGuardRequest(body_content=body, headers=headers)


@pytest.mark.redos_timing
async def test_no_false_negative_under_concurrent_redos_async() -> None:
    redos_request = _json_body_request(_REDOS_PAYLOAD)
    benign_request = _json_body_request(_BENIGN_MATCHING_PAYLOAD)

    tasks = []
    for _ in range(_CONCURRENCY):
        tasks.append(detect_penetration_attempt(redos_request, _CONFIG))
    tasks.append(detect_penetration_attempt(benign_request, _CONFIG))

    start = time.monotonic()
    results = await asyncio.gather(*tasks)
    elapsed = time.monotonic() - start

    assert results[-1].is_threat, (
        f"Benign matching payload was not detected under concurrent ReDoS load "
        f"(false negative). Elapsed: {elapsed:.2f}s"
    )
    assert elapsed < _DEADLINE_SECONDS, (
        f"Concurrent detect calls hung. Elapsed: {elapsed:.2f}s"
    )


@pytest.mark.redos_timing
async def test_concurrent_custom_and_benign_no_false_negative_async() -> None:
    await SusPatternsManager.add_pattern(_CUSTOM_PATTERN, custom=True)
    custom_payload = f"{_CUSTOM_MARKER}99"
    benign_payload = _BENIGN_MATCHING_PAYLOAD

    async def _custom_detect() -> DetectionResult:
        return await sus_patterns_handler.detect(
            custom_payload, "1.2.3.4", "request_body"
        )

    async def _benign_detect() -> DetectionResult:
        return await sus_patterns_handler.detect(
            benign_payload, "5.6.7.8", "request_body"
        )

    tasks = [_custom_detect() for _ in range(4)] + [_benign_detect()]

    start = time.monotonic()
    results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=15.0)
    elapsed = time.monotonic() - start

    benign_result = results[-1]
    assert benign_result["is_threat"] is True, (
        f"benign payload was not detected under concurrent custom load: "
        f"elapsed={elapsed:.2f}s"
    )
    assert elapsed < 15.0


@pytest.mark.redos_timing
async def test_slipping_custom_pattern_detect_completes_async() -> None:
    slipping = re.compile(r"(\w|\w)*x")
    compiled_tuple = (slipping, frozenset({"request_body", "unknown"}), "custom")
    sus_patterns_handler.compiled_custom_patterns.add(compiled_tuple)

    payload = "a" * 22

    async def _detect() -> object:
        return await sus_patterns_handler.detect(payload, "1.2.3.4", "request_body")

    start = time.monotonic()
    result = await asyncio.wait_for(_detect(), timeout=10.0)
    elapsed = time.monotonic() - start

    assert isinstance(result, dict)
    assert "is_threat" in result
    assert elapsed < 10.0
