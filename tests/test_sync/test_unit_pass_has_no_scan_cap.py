import json
from unittest.mock import patch

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils import scan_remainder
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_ATTACK = "/etc/passwd"
_PAST_THE_VALUE_CAP = 512


def _values_then_attack(decoding_needed: int) -> dict[str, str]:
    values = {f"a{i}": "x" for i in range(_PAST_THE_VALUE_CAP)}
    values.update({f"d{i}": "café" for i in range(decoding_needed)})
    values["z"] = _ATTACK
    return values


def _json_request(values: dict[str, str]) -> SyncMockGuardRequest:
    body = json.dumps(values).encode()
    return SyncMockGuardRequest(
        method="POST",
        headers={"content-type": "application/json", "content-length": str(len(body))},
        body_content=body,
    )


def _config() -> SyncSecurityConfig:
    return SyncSecurityConfig(enable_redis=False, enable_penetration_detection=True)


@pytest.mark.parametrize("decoding_needed", [255, 256, 257, 600, 2000])
def test_json_value_past_the_cap_gets_the_whole_value_rows(
    decoding_needed: int,
) -> None:
    request = _json_request(_values_then_attack(decoding_needed))

    result = detect_penetration_attempt(request, _config())

    assert result.is_threat is True


@pytest.mark.parametrize("decoding_needed", [255, 256, 257, 600])
def test_header_value_past_the_cap_gets_the_whole_value_rows(
    decoding_needed: int,
) -> None:
    headers = {
        f"x-{name}": value
        for name, value in _values_then_attack(decoding_needed).items()
    }

    result = detect_penetration_attempt(
        SyncMockGuardRequest(headers=headers), _config()
    )

    assert result.is_threat is True


def test_an_ended_time_budget_is_an_incomplete_scan_never_a_pass() -> None:
    request = _json_request(_values_then_attack(300))

    with patch.object(scan_remainder, "_scan_time_budget_exhausted", lambda: True):
        result = detect_penetration_attempt(request, _config())

    assert result.body_read_error
    assert result.is_threat is False
