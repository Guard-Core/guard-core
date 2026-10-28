import json
from unittest.mock import patch

import pytest

from guard_core._utils import scan_remainder
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

_ATTACK = "/etc/passwd"
_PAST_THE_VALUE_CAP = 512


def _values_then_attack(decoding_needed: int) -> dict[str, str]:
    values = {f"a{i}": "x" for i in range(_PAST_THE_VALUE_CAP)}
    values.update({f"d{i}": "café" for i in range(decoding_needed)})
    values["z"] = _ATTACK
    return values


def _json_request(values: dict[str, str]) -> MockGuardRequest:
    body = json.dumps(values).encode()
    return MockGuardRequest(
        method="POST",
        headers={"content-type": "application/json", "content-length": str(len(body))},
        body_content=body,
    )


def _config() -> SecurityConfig:
    return SecurityConfig(enable_redis=False, enable_penetration_detection=True)


@pytest.mark.parametrize("decoding_needed", [255, 256, 257, 600, 2000])
async def test_json_value_past_the_cap_gets_the_whole_value_rows(
    decoding_needed: int,
) -> None:
    request = _json_request(_values_then_attack(decoding_needed))

    result = await detect_penetration_attempt(request, _config())

    assert result.is_threat is True


@pytest.mark.parametrize("decoding_needed", [255, 256, 257, 600])
async def test_header_value_past_the_cap_gets_the_whole_value_rows(
    decoding_needed: int,
) -> None:
    headers = {
        f"x-{name}": value
        for name, value in _values_then_attack(decoding_needed).items()
    }

    result = await detect_penetration_attempt(
        MockGuardRequest(headers=headers), _config()
    )

    assert result.is_threat is True


async def test_an_ended_time_budget_is_an_incomplete_scan_never_a_pass() -> None:
    request = _json_request(_values_then_attack(300))

    with patch.object(scan_remainder, "_scan_time_budget_exhausted", lambda: True):
        result = await detect_penetration_attempt(request, _config())

    assert result.body_read_error
    assert result.is_threat is False
