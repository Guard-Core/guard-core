from urllib.parse import unquote

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_detection.benign_prompt_corpus import BENIGN_PROMPTS
from tests.test_sync.conftest import SyncMockGuardRequest

FFFD = "\ufffd"
PICKLE_TAIL = "cshutil\nrmtree\n(S'/tmp/x'\ntR."


def _as_the_framework_decodes(raw_request_text: str) -> str:
    return unquote(raw_request_text, errors="replace")


def _categories(request: SyncMockGuardRequest) -> list[str] | None:
    config = SyncSecurityConfig(enable_redis=False, rate_limit=1000)
    result = detect_penetration_attempt(request, config)
    return sorted(result.threat_categories) if result.is_threat else None


@pytest.mark.parametrize(
    "raw_query_value",
    [
        "%80%04" + PICKLE_TAIL,
        "%88" + PICKLE_TAIL,
        "%80%04%95%1c%00%00%00%00%00%00%00" + PICKLE_TAIL,
    ],
)
def test_pickle_global_opcode_with_a_lost_lead_byte_is_deserialization(
    raw_query_value: str,
) -> None:
    decoded = _as_the_framework_decodes(raw_query_value)
    assert FFFD in decoded
    request = SyncMockGuardRequest(path="/x", query_params={"q": decoded})
    assert _categories(request) == ["deserialization"]


@pytest.mark.parametrize(
    "raw_query_value",
    [
        "cshutil\nrmtree\nX\x06\x00\x00\x00/tmp/x%85R.",
        "cshutil\nrmtree\n%8c\x06/tmp/x%85R.",
        "%80\x02cshutil\nrmtree\n%8c\x06/tmp/x%85R.",
    ],
)
def test_pickle_global_opcode_with_a_lost_byte_after_the_row_is_deserialization(
    raw_query_value: str,
) -> None:
    decoded = _as_the_framework_decodes(raw_query_value)
    assert FFFD in decoded
    request = SyncMockGuardRequest(path="/x", query_params={"q": decoded})
    assert _categories(request) == ["deserialization"]


@pytest.mark.parametrize(
    "raw_query_value",
    ["\udc80\x04" + PICKLE_TAIL, "\udc88" + PICKLE_TAIL],
)
def test_pickle_global_opcode_with_a_raw_lead_byte_stays_deserialization(
    raw_query_value: str,
) -> None:
    request = SyncMockGuardRequest(path="/x", query_params={"q": raw_query_value})
    assert _categories(request) == ["deserialization"]


@pytest.mark.parametrize(
    "raw_path",
    ["/..%c0%2fconfig.yaml", "/..%c0%afconfig.yaml", "/%c0%ae%c0%ae/etc/passwd"],
)
def test_overlong_traversal_path_with_lost_bytes_matches_its_literal_form(
    raw_path: str,
) -> None:
    decoded = _as_the_framework_decodes(raw_path)
    assert FFFD in decoded
    literal = _categories(SyncMockGuardRequest(path=raw_path))
    assert literal is not None
    assert "path_traversal" in literal
    decoded_categories = _categories(SyncMockGuardRequest(path=decoded))
    assert decoded_categories is not None
    assert "path_traversal" in decoded_categories


@pytest.mark.parametrize("surface", ["query", "header"])
@pytest.mark.parametrize("raw_value", ["..%c0%2fconfig.yaml", "..%c0%afconfig.yaml"])
def test_overlong_traversal_value_with_lost_bytes_is_path_traversal(
    surface: str, raw_value: str
) -> None:
    decoded = _as_the_framework_decodes(raw_value)
    request = (
        SyncMockGuardRequest(path="/x", query_params={"q": decoded})
        if surface == "query"
        else SyncMockGuardRequest(path="/x", headers={"x-custom": decoded})
    )
    categories = _categories(request)
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
def test_text_that_merely_holds_a_replacement_char_is_not_flagged(
    value: str,
) -> None:
    request = SyncMockGuardRequest(path="/x", query_params={"q": value})
    assert _categories(request) is None


@pytest.mark.parametrize("value", [p for p in BENIGN_PROMPTS if FFFD not in p][:200])
def test_benign_prompts_with_a_replacement_char_added_are_not_flagged_by_it(
    value: str,
) -> None:
    plain = _categories(SyncMockGuardRequest(path="/x", query_params={"q": value}))
    with_char = _categories(
        SyncMockGuardRequest(path="/x", query_params={"q": f"{FFFD}{value}{FFFD}"})
    )
    assert with_char == plain


def _body_categories(body: bytes, content_type: str) -> list[str] | None:
    request = SyncMockGuardRequest(
        path="/x",
        method="POST",
        headers={"content-type": content_type, "content-length": str(len(body))},
        body_content=body,
    )
    return _categories(request)


@pytest.mark.parametrize(
    ("body", "content_type"),
    [
        (b"..\xc0\xafconfig.yaml", "text/plain"),
        (b"q=..\xc0\xafconfig.yaml", "application/x-www-form-urlencoded"),
        (b"/%c0%ae%c0%ae/etc/passwd".replace(b"%c0%ae", b"\xc0\xae"), "text/plain"),
    ],
)
def test_overlong_traversal_in_raw_body_bytes_is_path_traversal(
    body: bytes, content_type: str
) -> None:
    categories = _body_categories(body, content_type)
    assert categories is not None
    assert "path_traversal" in categories


@pytest.mark.parametrize(
    ("body", "content_type"),
    [
        (b"caf\xe9 au lait", "text/plain"),
        (b"q=caf\xe9+au+lait", "application/x-www-form-urlencoded"),
        (b"notes/..\xc0 are fine", "text/plain"),
    ],
)
def test_invalid_utf8_in_a_benign_body_stays_clean(
    body: bytes, content_type: str
) -> None:
    assert _body_categories(body, content_type) is None
