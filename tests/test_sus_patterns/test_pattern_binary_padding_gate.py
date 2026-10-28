import random

import pytest

from guard_core.handlers.suspatterns_handler import DetectionResult, SusPatternsManager

_BODY_CONTEXT = "request_body"
_PADDING_BYTES = 4096
_TEXT_NEIGHBOURHOOD = " a short note: "


def _high_byte_padding(seed: int) -> str:
    rng = random.Random(seed)
    raw = bytes(rng.randrange(128, 256) for _ in range(_PADDING_BYTES))
    return raw.decode("utf-8", errors="surrogateescape")


async def _detect(manager: SusPatternsManager, payload: str) -> DetectionResult:
    return await manager.detect(payload, "127.0.0.1", context=_BODY_CONTEXT)


@pytest.mark.parametrize("seed", [1, 2, 3])
@pytest.mark.parametrize("attack", ["; cat /etc/passwd", "$(cat /etc/passwd)"])
async def test_command_in_text_between_binary_padding_is_flagged(
    sus_patterns_manager_with_detection: SusPatternsManager,
    seed: int,
    attack: str,
) -> None:
    padding = _high_byte_padding(seed)
    result = await _detect(
        sus_patterns_manager_with_detection,
        f"{padding}{_TEXT_NEIGHBOURHOOD}{attack}{_TEXT_NEIGHBOURHOOD}{padding}",
    )
    assert result["is_threat"] is True


@pytest.mark.parametrize("seed", [1, 2, 3])
async def test_command_glued_to_binary_padding_stays_noise(
    sus_patterns_manager_with_detection: SusPatternsManager, seed: int
) -> None:
    padding = _high_byte_padding(seed)
    result = await _detect(
        sus_patterns_manager_with_detection,
        f"{padding}; cat /etc/passwd{padding}",
    )
    assert result["is_threat"] is False
