import base64
import binascii
import random
import re
import string

from guard_core.detection_engine import base64_view
from guard_core.detection_engine.preprocessor import ContentPreprocessor
from guard_core.detection_engine.semantic import looks_like_binary_content
from guard_core.handlers._suspatterns_literals import (
    fold_for_literals,
    required_literals,
    rows_with_required_literal,
)
from guard_core.handlers._suspatterns_shell_sources import (
    _GLOB_WILDCARD_ATOM_RE,
    _glob_wildcard_scan_matches,
)


def _reference_looks_like_binary_content(content: str) -> bool:
    if not content:
        return False
    non_text_count = sum(
        1
        for ch in content
        if ch not in "\t\r\n" and (not ch.isprintable() or ch == "�")
    )
    return non_text_count / len(content) >= 0.2


def _reference_decode_candidate(token: str) -> str | None:
    if len(token) > base64_view.MAX_SHORT_BASE64_TOKEN_LENGTH:
        return None
    padding = (4 - len(token) % 4) % 4
    try:
        raw = base64.b64decode(token + "=" * padding, validate=True)
        decoded = raw.decode("utf-8")
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    printable = sum(1 for char in decoded if char.isprintable())
    if printable / len(decoded) < base64_view.PRINTABLE_RATIO_THRESHOLD:
        return None
    if not any(char in base64_view.SHORT_BASE64_MARKER_CHARS for char in decoded):
        return None
    return decoded


def _reference_additive_view(content: str) -> str:
    pre = ContentPreprocessor()
    content = pre.truncate_safely(pre.normalize_unicode(content))
    fragments = []
    for attempts, match in enumerate(
        base64_view.SHORT_BASE64_TOKEN_RE.finditer(content)
    ):
        if attempts >= base64_view.MAX_SHORT_BASE64_CANDIDATES:
            break
        decoded = _reference_decode_candidate(match.group(0))
        if decoded is not None:
            fragments.append(decoded)
    return "\n".join(fragments)


def test_the_binary_content_check_matches_its_per_character_definition() -> None:
    generator = random.Random(3)
    pool = list("abc xyz \t\r\n\x00\x01\x7f�​ é漢😀") + list("abcdefgh") * 4
    for _ in range(3000):
        text = "".join(generator.choice(pool) for _ in range(generator.randint(0, 40)))
        assert looks_like_binary_content(text) == _reference_looks_like_binary_content(
            text
        )


def test_the_short_base64_view_matches_the_validate_true_definition() -> None:
    generator = random.Random(11)
    alphabet = string.ascii_letters + string.digits + "+/"
    words = ["lorem", "${jndi:x}", "JHtqbmRp", "e3t9fQ==", "I2lk", "$(id)", "QUJD"]
    preprocessor = ContentPreprocessor()
    for _ in range(1500):
        parts = []
        for _ in range(generator.randint(1, 12)):
            roll = generator.random()
            if roll < 0.4:
                parts.append(
                    "".join(
                        generator.choice(alphabet)
                        for _ in range(generator.randint(1, 16))
                    )
                )
            elif roll < 0.7:
                payload = "".join(generator.choice("${}#ab c\n") for _ in range(5))
                encoded = base64.b64encode(payload.encode()).decode()
                parts.append(encoded[: generator.randint(4, 14)])
            else:
                parts.append(generator.choice(words))
        text = generator.choice([" ", "", "=", "\n", ".", ","]).join(parts)
        assert base64_view.build_short_base64_additive_view(
            preprocessor, text
        ) == _reference_additive_view(text)


def test_the_glob_scan_skips_text_without_a_wildcard_and_matches_otherwise() -> None:
    compiled = re.compile(_GLOB_WILDCARD_ATOM_RE, re.IGNORECASE)
    assert _glob_wildcard_scan_matches("cat /etc/pass", compiled) == []
    assert [m.group() for m in _glob_wildcard_scan_matches("ls /e*c/p?ss", compiled)]


def test_the_literal_prefilter_keeps_exactly_the_rows_whose_literal_is_present() -> (
    None
):
    rows = [
        (re.compile(source), frozenset({"unknown"}), "sqli")
        for source in (
            r"(?i)UNION\s+SELECT",
            r"(?i)SLEEP\s*\(",
            r"\d+",
            r"(?i)(?:WAITFOR|BENCHMARK)\s*\(",
        )
    ]
    for content in ("1 union select x", "sleep(5) and 7", "plain", "benchmark(1)"):
        folded = fold_for_literals(content)
        expected = [
            row
            for row in rows
            if not required_literals(row[0].pattern)
            or any(lit in folded for lit in required_literals(row[0].pattern))
        ]
        assert list(rows_with_required_literal(rows, folded, frozenset())) == expected
