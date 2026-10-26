import json
from pathlib import Path

from guard_core.models import SyncSecurityConfig
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

# Stored verdicts from ledger_gaps/verify/inv-6207 (generated set, seed 6207) and
# ledger_gaps/verify/wp134/build_data.py, never computed at test time (D-74, zero loss
# against v4.4.0). "flagged_comment_gap" holds the 77 values with a real select list
# or tail and a "/**/" gap that v4.4.0 flagged and landing-6d stopped flagging
# (their comment-free twins were flagged), with the surfaces v4.4.0 flagged.
# "flagged_unclosed_leading_comment" holds 6 values of LEDGER 6.211 (a leading "/*"
# that never closes, or closes after the keywords) with the surfaces v4.4.0 flagged.
# "clean_bare_word" holds the 44 values whose select list is one bare word (D-18,
# D-70): their verdicts stay what landing-6d gave. "benign" holds 400 prose values
# with the v4.4.0 and landing-6d verdicts: nothing is flagged that v4.4.0 did not
# flag, and nothing changes against landing-6d.
_TESTS_DIR = next(parent for parent in Path(__file__).parents if parent.name == "tests")
_DATA = json.loads(
    (
        _TESTS_DIR / "test_detection" / "data" / "comment_gap_union_select_v440.json"
    ).read_text()
)
_SURFACES = _DATA["surfaces"]


def _request(surface: str, value: str) -> SyncMockGuardRequest:
    if surface == "query":
        return SyncMockGuardRequest(path="/x", query_params={"q": value})
    if surface == "header":
        return SyncMockGuardRequest(
            path="/x",
            headers={"x-custom": value.replace("\n", " ").replace("\r", " ")},
        )
    return SyncMockGuardRequest(path="/" + value.replace("?", "").replace("#", ""))


def _is_threat(surface: str, value: str) -> bool:
    config = SyncSecurityConfig(enable_redis=False)
    return bool(
        (detect_penetration_attempt(_request(surface, value), config)).is_threat
    )


def test_every_comment_gap_union_select_with_a_list_is_flagged_as_v440_did() -> None:
    missed = [
        (value, surface)
        for value, surfaces in _DATA["flagged_comment_gap"]
        for surface in surfaces
        if not _is_threat(surface, value)
    ]
    assert len(_DATA["flagged_comment_gap"]) == 77
    assert missed == []


def test_an_unclosed_leading_comment_before_union_select_is_flagged() -> None:
    missed = [
        (value, surface)
        for value, surfaces in _DATA["flagged_unclosed_leading_comment"]
        for surface in surfaces
        if not _is_threat(surface, value)
    ]
    assert len(_DATA["flagged_unclosed_leading_comment"]) == 6
    assert missed == []


def test_a_bare_word_select_list_keeps_its_landing_verdict() -> None:
    changed = [
        (value, surface)
        for value, expected in _DATA["clean_bare_word"]
        for surface, was_flagged in zip(_SURFACES, expected, strict=True)
        if _is_threat(surface, value) != was_flagged
    ]
    assert len(_DATA["clean_bare_word"]) == 44
    assert changed == []


def test_benign_prose_gains_no_flag_over_v440_and_none_over_the_landing() -> None:
    gained = []
    changed = []
    for value, v440, landing in _DATA["benign"]:
        for surface, was_v440, was_landing in zip(
            _SURFACES, v440, landing, strict=True
        ):
            flagged = _is_threat(surface, value)
            if flagged and not was_v440:
                gained.append((value, surface))
            if flagged != was_landing:
                changed.append((value, surface))
    assert len(_DATA["benign"]) == 400
    assert gained == []
    assert changed == []
