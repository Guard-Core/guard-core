import re

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.detection_scan import (
    _USER_AGENT_WINDOW_STRIDE,
    _search_user_agent_windows,
)
from guard_core.sync.utils import (
    _MAX_USER_AGENT_MATCH_LENGTH,
    is_user_agent_allowed,
)

FLAGS = re.IGNORECASE | re.MULTILINE
STRIDE = _USER_AGENT_WINDOW_STRIDE
PATTERNS = [
    "curl",
    "bot",
    "^curl",
    "curl$",
    "bot$",
    r"\bbot\b",
    r"bot\b",
    r"\bbot",
    r"bot(?=x)",
    r"bot(?!x)",
    r"(?<=x)bot",
    r"(?<!x)bot",
    r"bad-?scanner[0-9]*",
    r"(?:sqlmap|nikto|masscan)",
    r"^Mozilla.*curl/8",
]


def _verdict(pattern: str, text: str) -> bool:
    return _search_user_agent_windows(re.compile(pattern, FLAGS), text) is not None


def _full(pattern: str, text: str) -> bool:
    return re.compile(pattern, FLAGS).search(text) is not None


def test_window_size_and_stride_are_the_validated_512_with_256_overlap() -> None:
    assert _MAX_USER_AGENT_MATCH_LENGTH == 512
    assert STRIDE == 256


@pytest.mark.parametrize("padding", [600, 2000, 8000])
def test_blocked_name_after_long_padding_is_found(padding: int) -> None:
    config = SyncSecurityConfig(blocked_user_agents=["evilscanner"])
    user_agent = "a" * padding + "evilscanner/1.0"
    assert is_user_agent_allowed(user_agent, config) is False


def test_benign_long_user_agent_is_allowed() -> None:
    config = SyncSecurityConfig(blocked_user_agents=["evilscanner"])
    assert is_user_agent_allowed("a" * 8000, config) is True


def test_caret_matches_only_at_the_real_start() -> None:
    text = "Mozilla/5.0 " + "x" * 1000 + " curl/8"
    assert _verdict("^curl", text) is False
    assert _verdict("^curl", "curl/8 " + "x" * 1000) is True
    assert _verdict("^curl", "x" * STRIDE + "curl/8" + "x" * 1000) is False


def test_dollar_does_not_match_at_a_non_final_window_end() -> None:
    for suffix in ("curl", "bot"):
        end = _MAX_USER_AGENT_MATCH_LENGTH
        text = "a" * (end - len(suffix)) + suffix + "ics" + "a" * 1000
        assert _verdict(suffix + "$", text) is False
    robotics = "a" * (_MAX_USER_AGENT_MATCH_LENGTH - 3) + "robotics" + "a" * 600
    assert _verdict("bot$", robotics) is False


def test_dollar_matches_at_the_real_end() -> None:
    assert _verdict("curl$", "a" * 3000 + "curl") is True
    assert _verdict("bot$", "a" * 3000 + "robot") is True


def test_word_boundary_and_lookahead_give_the_full_search_verdict() -> None:
    cut = _MAX_USER_AGENT_MATCH_LENGTH - 3
    for pattern in (r"\bbot\b", r"bot\b", r"bot(?=x)", r"bot(?!x)"):
        for tail in ("x", " ", ""):
            text = "a " * (cut // 2) + "bot" + tail + " " + "a " * 600
            assert _verdict(pattern, text) is _full(pattern, text), (pattern, tail)


@pytest.mark.parametrize("length", [100, 511, 512, 513, 800, 2000, 8000])
def test_name_straddling_every_window_seam_is_found(length: int) -> None:
    name = "badscanner99"
    for seam in range(STRIDE, length, STRIDE):
        for shift in range(-len(name), 1):
            at = seam + shift
            if at < 0 or at + len(name) > length:
                continue
            text = "a" * at + name + "a" * (length - at - len(name))
            assert _verdict(r"badscanner[0-9]*", text), (length, at)


def test_differential_against_full_string_search() -> None:
    names = ["curl", "bot", "robot", "botx", "xbot", "badscanner42", "sqlmap"]
    differing = 0
    cases = 0
    for length in (100, 300, 512, 513, 600, 768, 1024, 2000, 4096, 8000):
        seams = [0, *range(STRIDE - 8, length, STRIDE)]
        for at in seams:
            for name in names:
                for tail in ("", "x", " ", "ics"):
                    piece = name + tail
                    if at + len(piece) > length:
                        continue
                    text = "Mozilla " * 0 + "a " * (at // 2)
                    text += piece
                    text += " b" * ((length - len(text)) // 2)
                    for pattern in PATTERNS:
                        cases += 1
                        differing += _verdict(pattern, text) is not _full(pattern, text)
    assert cases > 10000
    assert differing == 0
