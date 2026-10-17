import io
import random
import time
import zipfile

import pytest

from guard_core.handlers import _suspatterns_regex, _suspatterns_sources
from guard_core.handlers._suspatterns_pattern_table import (
    NOISE_PRONE_PATTERN_SOURCES,
)
from guard_core.handlers.suspatterns_handler import SusPatternsManager

_MULTIPART_FIELD_CONTEXT = "request_body:multipart_field"
_NOISE_SEEDS = (1, 2, 3, 42, 1337)
_NOISE_SIZE = 262144
_DECODED_VIEWS = ("latin-1", "utf-8-surrogateescape")

_ATTACK_PAYLOADS = (
    "`rm -rf /`",
    "$(cat /etc/passwd)",
    "c'a't config.ini",
    "'; DROP TABLE users;--",
    "../../../etc/passwd",
)

_PLAIN_TEXT_SAMPLES = (
    "Café résumé naïve décor sélection",
    "日本語のテキストです。中国語與繁體字。한국어 텍스트",
    "кириллица и русский текст",
)


def _noise_bytes(seed: int) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.randrange(256) for _ in range(_NOISE_SIZE))


def _decoded_noise(seed: int, decoding: str) -> str:
    raw = _noise_bytes(seed)
    if decoding == "latin-1":
        return raw.decode("latin-1")
    return raw.decode("utf-8", errors="surrogateescape")


def _zip_bytes(seed: int) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("attachment.bin", _noise_bytes(seed)[:50000])
    return buffer.getvalue()


async def _detect(manager: SusPatternsManager, payload: str) -> dict:
    return await manager.detect(payload, "127.0.0.1", context=_MULTIPART_FIELD_CONTEXT)


@pytest.mark.asyncio
@pytest.mark.parametrize("decoding", _DECODED_VIEWS)
@pytest.mark.parametrize("seed", _NOISE_SEEDS)
async def test_random_binary_noise_produces_zero_threats(
    sus_patterns_manager_with_detection: SusPatternsManager,
    seed: int,
    decoding: str,
) -> None:
    result = await _detect(
        sus_patterns_manager_with_detection, _decoded_noise(seed, decoding)
    )
    assert result["is_threat"] is False
    assert result["threats"] == []


@pytest.mark.asyncio
async def test_zip_upload_produces_zero_threats(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    result = await _detect(
        sus_patterns_manager_with_detection,
        _zip_bytes(seed=11).decode("utf-8", errors="surrogateescape"),
    )
    assert result["is_threat"] is False
    assert result["threats"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", _ATTACK_PAYLOADS)
async def test_real_payloads_still_detected(
    sus_patterns_manager_with_detection: SusPatternsManager,
    payload: str,
) -> None:
    result = await _detect(sus_patterns_manager_with_detection, payload)
    assert result["is_threat"] is True
    assert result["threats"]


@pytest.mark.asyncio
@pytest.mark.parametrize("sample", _PLAIN_TEXT_SAMPLES)
async def test_non_latin_text_without_payload_not_flagged(
    sus_patterns_manager_with_detection: SusPatternsManager,
    sample: str,
) -> None:
    result = await _detect(sus_patterns_manager_with_detection, sample)
    assert result["is_threat"] is False
    assert result["threats"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("sample", _PLAIN_TEXT_SAMPLES)
async def test_non_latin_text_with_embedded_backtick_still_detected(
    sus_patterns_manager_with_detection: SusPatternsManager,
    sample: str,
) -> None:
    result = await _detect(sus_patterns_manager_with_detection, f"{sample}; `rm -rf /`")
    assert result["is_threat"] is True
    assert result["threats"]


@pytest.mark.asyncio
async def test_payload_near_string_start_still_detected(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    result = await _detect(
        sus_patterns_manager_with_detection,
        "../../../etc/passwd and more prose here",
    )
    assert result["is_threat"] is True


@pytest.mark.asyncio
async def test_payload_near_string_end_still_detected(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    result = await _detect(
        sus_patterns_manager_with_detection,
        "prose " * 30 + "../../../etc/passwd",
    )
    assert result["is_threat"] is True


@pytest.mark.asyncio
async def test_short_value_below_window_margin_still_detected(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    result = await _detect(
        sus_patterns_manager_with_detection,
        "café '; DELETE FROM users;--",
    )
    assert result["is_threat"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "control_only",
    [
        "\x00" * 500,
        "".join(chr(i) for i in range(1, 32)) * 40,
        "\x7f" * 300,
    ],
)
async def test_control_char_only_value_not_flagged(
    sus_patterns_manager_with_detection: SusPatternsManager,
    control_only: str,
) -> None:
    result = await _detect(sus_patterns_manager_with_detection, control_only)
    assert result["is_threat"] is False
    assert result["threats"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        "\x85" * 200 + ".." + "\x9f\x9e\x9d\x9c" + "/" + "\x87" * 200,
        "\x85" * 200 + "$(cat /etc/passwd)" + "\x87" * 200,
    ],
)
async def test_payload_fragment_buried_in_binary_noise_not_flagged(
    sus_patterns_manager_with_detection: SusPatternsManager,
    payload: str,
) -> None:
    result = await _detect(sus_patterns_manager_with_detection, payload)
    assert result["is_threat"] is False
    assert result["threats"] == []


@pytest.mark.asyncio
async def test_binary_noise_scan_takes_under_five_cpu_seconds(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    started = time.process_time()
    result = await _detect(
        sus_patterns_manager_with_detection, _decoded_noise(seed=3, decoding="latin-1")
    )
    elapsed = time.process_time() - started
    assert result["is_threat"] is False
    assert not any(t["type"] == "pattern_timeout" for t in result["threats"])
    assert elapsed < 5.0


@pytest.mark.asyncio
async def test_noise_prone_registry_is_truthful(
    sus_patterns_manager_with_detection: SusPatternsManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        _suspatterns_regex, "match_is_binary_dense", lambda _prefix, _match: False
    )
    matched_sources: set[str] = set()
    for seed in _NOISE_SEEDS:
        for decoding in _DECODED_VIEWS:
            result = await _detect(
                sus_patterns_manager_with_detection,
                _decoded_noise(seed, decoding),
            )
            matched_sources.update(t["pattern"] for t in result["threats"])
    # Sources whose shape requires a specific trigram/terminator run (e.g. the
    # SQLi comment terminator "'\n--") cannot be expected to occur in pure
    # random noise; their registry membership and suppression are covered by
    # dedicated tests below.
    trigram_shaped_sources = {
        _suspatterns_sources._SQLI_COMMENT_TERMINATOR_RE,
    }
    assert NOISE_PRONE_PATTERN_SOURCES - trigram_shaped_sources <= matched_sources
    assert (
        _suspatterns_sources._SQLI_COMMENT_TERMINATOR_RE in NOISE_PRONE_PATTERN_SOURCES
    )


_PDF_BINARY_PREFIX = (
    b"%PDF-1.4\n%\xc7\x8f\xa2\n7 0 obj\n<</Length 8 0 R/Filter /FlateDecode>>\nstream\n"
)
_SQLI_TERMINATOR_IN_BINARY = b"'\n--"


@pytest.mark.asyncio
async def test_pdf_comment_line_with_sqli_terminator_bytes_not_flagged(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    """A PDF header whose binary comment region contains an apostrophe, a
    newline and dashes must not be reported as SQLi (regression for the
    real-world 558KB-PDF false positive)."""
    buffer = bytearray(_PDF_BINARY_PREFIX)
    buffer += _noise_bytes(seed=11)[:2000]
    buffer[100:104] = _SQLI_TERMINATOR_IN_BINARY
    payload = bytes(buffer).decode("utf-8", errors="surrogateescape")

    result = await _detect(sus_patterns_manager_with_detection, payload)

    assert result["is_threat"] is False
    assert result["threats"] == []


@pytest.mark.asyncio
async def test_ascii_sqli_comment_terminator_outside_binary_still_detected(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    """The noise gate must not swallow genuine ASCII SQLi comment terminators."""
    payload = "users?name=1=1' \n-- drop table users"

    result = await _detect(sus_patterns_manager_with_detection, payload)

    assert result["is_threat"] is True
    assert any(t.get("category") == "sqli" for t in result["threats"])


@pytest.mark.asyncio
async def test_sqli_comment_terminator_source_is_noise_gated(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    """The SQLi comment-terminator source is registered as noise-prone: a match
    whose neighborhood is binary-dense must be dropped by _build_regex_threat,
    while the same match in ASCII surroundings survives (covered by the
    still_detected test below)."""
    import re as _re

    from guard_core.detection_engine.binary_prefix import build_binary_prefix
    from guard_core.handlers import _suspatterns_regex as regex_module
    from guard_core.handlers._suspatterns_sources import (
        _SQLI_COMMENT_TERMINATOR_RE,
    )

    dense_noise = _decoded_noise(seed=11, decoding="utf-8-surrogateescape")[:200]
    text = "abc \n" + "' \n--" + dense_noise
    compiled = _re.compile(_SQLI_COMMENT_TERMINATOR_RE)
    match = compiled.search(text)
    assert match is not None

    binary_prefix = build_binary_prefix(text)
    threat = regex_module._build_regex_threat(
        compiled,
        match,
        "sqli",
        time.monotonic(),
        "request_body",
        binary_prefix=binary_prefix,
    )
    assert threat is None
