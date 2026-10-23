import json
import logging

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_BUDGET_WARNING_TEXT = "detection_max_scan_chars (1024) reached"


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


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


def test_char_budget_warning_fires_once_across_many_skipped_values(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(detection_max_scan_chars=1024)
    payload = {f"k{i}": "x" * 200 for i in range(10)}
    request = _json_body_request(payload)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is False
    assert caplog.text.count(_BUDGET_WARNING_TEXT) == 1


def test_embedded_json_value_char_budget_skips_remaining_fields(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SyncSecurityConfig(detection_max_scan_chars=1024)
    embedded = json.dumps({f"k{i}": "x" * 200 for i in range(10)})
    request = SyncMockGuardRequest(query_params={"filters": embedded})

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        result = detect_penetration_attempt(request, config)

    assert result.is_threat is False
    assert caplog.text.count(_BUDGET_WARNING_TEXT) == 1
