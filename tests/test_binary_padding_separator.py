import pytest

from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

_HIGH = bytes([0x80 + (index * 37) % 128 for index in range(4096)])
_COMMAND = b"; cat /etc/passwd"


class _BoundedReaderRequest(MockGuardRequest):
    async def read_body_prefix(self, max_bytes: int) -> bytes:
        return self._body[:max_bytes]


def _request(separator: bytes) -> MockGuardRequest:
    body = _HIGH + separator + _COMMAND + separator + _HIGH
    return _BoundedReaderRequest(
        method="POST",
        body_content=body,
        headers={"content-type": "text/plain", "content-length": str(len(body))},
    )


@pytest.mark.parametrize(
    "separator",
    [b" " * 8, b" " * 9, b" " * 20, b"\n" * 20, b"\t" * 12, b"x" * 8, b"x" * 20],
)
async def test_a_command_between_binary_blocks_is_flagged_whatever_the_padding(
    separator: bytes,
) -> None:
    result = await detect_penetration_attempt(
        _request(separator), SecurityConfig(enable_redis=False)
    )

    assert result.is_threat is True


async def test_the_same_command_inside_pure_binary_noise_is_still_noise() -> None:
    body = _HIGH + b";cat /etc/passwd" + _HIGH
    request = _BoundedReaderRequest(
        method="POST",
        body_content=body,
        headers={"content-type": "text/plain", "content-length": str(len(body))},
    )

    result = await detect_penetration_attempt(
        request, SecurityConfig(enable_redis=False)
    )

    assert result.is_threat is False
