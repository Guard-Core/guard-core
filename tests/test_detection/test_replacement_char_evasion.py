from urllib.parse import unquote

import pytest

from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest
from tests.test_detection.benign_prompt_corpus import BENIGN_PROMPTS

FFFD = "\ufffd"
PICKLE_TAIL = "cshutil\nrmtree\n(S'/tmp/x'\ntR."


def _as_the_framework_decodes(raw_request_text: str) -> str:
    return unquote(raw_request_text, errors="replace")


async def _categories(request: MockGuardRequest) -> list[str] | None:
    config = SecurityConfig(enable_redis=False, rate_limit=1000)
    result = await detect_penetration_attempt(request, config)
    return sorted(result.threat_categories) if result.is_threat else None


@pytest.mark.parametrize(
    "raw_query_value",
    [
        "%80%04" + PICKLE_TAIL,
        "%88" + PICKLE_TAIL,
        "%80%04%95%1c%00%00%00%00%00%00%00" + PICKLE_TAIL,
    ],
)
async def test_pickle_global_opcode_with_a_lost_lead_byte_is_deserialization(
    raw_query_value: str,
) -> None:
    decoded = _as_the_framework_decodes(raw_query_value)
    assert FFFD in decoded
    request = MockGuardRequest(path="/x", query_params={"q": decoded})
    assert await _categories(request) == ["deserialization"]


@pytest.mark.parametrize(
    "raw_query_value",
    ["\udc80\x04" + PICKLE_TAIL, "\udc88" + PICKLE_TAIL],
)
async def test_pickle_global_opcode_with_a_raw_lead_byte_stays_deserialization(
    raw_query_value: str,
) -> None:
    request = MockGuardRequest(path="/x", query_params={"q": raw_query_value})
    assert await _categories(request) == ["deserialization"]


@pytest.mark.parametrize(
    "raw_path",
    ["/..%c0%2fconfig.yaml", "/..%c0%afconfig.yaml", "/%c0%ae%c0%ae/etc/passwd"],
)
async def test_overlong_traversal_path_with_lost_bytes_matches_its_literal_form(
    raw_path: str,
) -> None:
    decoded = _as_the_framework_decodes(raw_path)
    assert FFFD in decoded
    literal = await _categories(MockGuardRequest(path=raw_path))
    assert literal is not None
    assert "path_traversal" in literal
    decoded_categories = await _categories(MockGuardRequest(path=decoded))
    assert decoded_categories is not None
    assert "path_traversal" in decoded_categories


@pytest.mark.parametrize("surface", ["query", "header"])
@pytest.mark.parametrize("raw_value", ["..%c0%2fconfig.yaml", "..%c0%afconfig.yaml"])
async def test_overlong_traversal_value_with_lost_bytes_is_path_traversal(
    surface: str, raw_value: str
) -> None:
    decoded = _as_the_framework_decodes(raw_value)
    request = (
        MockGuardRequest(path="/x", query_params={"q": decoded})
        if surface == "query"
        else MockGuardRequest(path="/x", headers={"x-custom": decoded})
    )
    categories = await _categories(request)
    assert categories is not None
    assert "path_traversal" in categories


@pytest.mark.parametrize(
    "value",
    [
        f"caf{FFFD} cshutil\nrmtree\n(S'/tmp/x'\ntR.",
        f"Price: {FFFD}5 cshutil\nrmtree\n(S'/tmp/x'\ntR.",
        f"{FFFD}" * 9 + PICKLE_TAIL,
        f"€{FFFD}" + PICKLE_TAIL,
        f"wait..{FFFD}{FFFD}done",
        f"see {FFFD}{FFFD}{FFFD}{FFFD}/notes",
        f"/docs/a{FFFD}/b",
        f"{FFFD}",
        f"loading...{FFFD}",
    ],
)
async def test_text_that_merely_holds_a_replacement_char_is_not_flagged(
    value: str,
) -> None:
    request = MockGuardRequest(path="/x", query_params={"q": value})
    assert await _categories(request) is None


@pytest.mark.parametrize("value", [p for p in BENIGN_PROMPTS if FFFD not in p][:200])
async def test_benign_prompts_with_a_replacement_char_added_are_not_flagged_by_it(
    value: str,
) -> None:
    plain = await _categories(MockGuardRequest(path="/x", query_params={"q": value}))
    with_char = await _categories(
        MockGuardRequest(path="/x", query_params={"q": f"{FFFD}{value}{FFFD}"})
    )
    assert with_char == plain
