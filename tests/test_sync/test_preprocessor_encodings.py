import re

import pytest

from guard_core.sync.detection_engine.preprocessor import ContentPreprocessor
from guard_core.sync.handlers.suspatterns_handler import SusPatternsManager

_CMD_INJECTION_PATTERNS = [
    re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    for pattern, _contexts, category in SusPatternsManager._pattern_definitions
    if category == "cmd_injection"
]


def _cmd_injection_detected(text: str) -> bool:
    return any(pattern.search(text) for pattern in _CMD_INJECTION_PATTERNS)


@pytest.fixture
def pp() -> ContentPreprocessor:
    return ContentPreprocessor(max_content_length=2000, preserve_attack_patterns=True)


def test_base64_payload_decoded(pp: ContentPreprocessor) -> None:
    payload = "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
    result = pp.preprocess(f"data: {payload}")
    assert "<script" in result.lower()


def test_hex_escape_decoded(pp: ContentPreprocessor) -> None:
    payload = r"\x3cscript\x3ealert(1)\x3c/script\x3e"
    result = pp.preprocess(payload)
    assert "<script" in result.lower()


def test_js_unicode_escape_decoded(pp: ContentPreprocessor) -> None:
    payload = r"\u003cscript\u003ealert(1)\u003c/script\u003e"
    result = pp.preprocess(payload)
    assert "<script" in result.lower()


def test_sql_block_comment_retained_not_fused(pp: ContentPreprocessor) -> None:
    payload = "SELE/**/CT password FRO/**/M users"
    result = pp.preprocess(payload)
    assert "/**/" in result
    assert "select" not in result.lower()


def test_sql_line_comment_stripped(pp: ContentPreprocessor) -> None:
    payload = "SELECT password -- harmless\nFROM users"
    result = pp.preprocess(payload)
    assert "from users" in result.lower()


def test_decode_iteration_cap_holds(pp: ContentPreprocessor) -> None:
    payload = "%2525253c" * 50
    result = pp.preprocess(payload)
    assert isinstance(result, str)


def test_hex_escape_invalid_value(pp: ContentPreprocessor) -> None:
    payload = r"\xGG"
    result = pp.preprocess(payload)
    assert isinstance(result, str)


def test_unicode_escape_invalid_value(pp: ContentPreprocessor) -> None:
    payload = r"\uZZZZ"
    result = pp.preprocess(payload)
    assert isinstance(result, str)


def test_base64_invalid_token_preserved(pp: ContentPreprocessor) -> None:
    payload = "not-valid-base64-but-long-enough-to-match!@#$%^&*()"
    result = pp.preprocess(payload)
    assert isinstance(result, str)


def test_base64_non_printable_preserved(pp: ContentPreprocessor) -> None:
    import base64

    binary_data = bytes(range(32))
    token = base64.b64encode(binary_data).decode("ascii")
    result = pp.preprocess(f"data: {token}")
    assert isinstance(result, str)


def test_sql_block_and_line_comments_combined(pp: ContentPreprocessor) -> None:
    payload = "SELECT/*comment*/ password -- line comment\nFROM users"
    result = pp.preprocess(payload)
    assert "select" in result.lower()
    assert "from" in result.lower()


def test_hex_escape_all_valid_chars(pp: ContentPreprocessor) -> None:
    payload = r"\x41\x42\x43"
    result = pp.preprocess(payload)
    assert "abc" in result.lower()


def test_ldap_hex_escape_decoded_in_preprocess(pp: ContentPreprocessor) -> None:
    payload = r"admin\29\28cn=\2a"
    result = pp.preprocess(payload)
    assert "admin)(cn=*" in result


def test_decode_hex_escapes_directly(pp: ContentPreprocessor) -> None:
    assert pp._decode_hex_escapes(r"\x41\x42") == "AB"


def test_decode_ldap_hex_escapes_directly(pp: ContentPreprocessor) -> None:
    assert pp._decode_ldap_hex_escapes(r"\29\28cn=\2a") == ")(cn=*"


def test_decode_unicode_escapes_directly(pp: ContentPreprocessor) -> None:
    assert pp._decode_unicode_escapes(r"AB") == "AB"


def test_strip_sql_comments_block(pp: ContentPreprocessor) -> None:
    assert pp._strip_sql_comments("SEL/*x*/ECT") == "SEL/*x*/ECT"


def test_strip_sql_comments_line(pp: ContentPreprocessor) -> None:
    result = pp._strip_sql_comments("SELECT -- comment\nFROM")
    assert "FROM" in result


def test_strip_sql_comments_hash(pp: ContentPreprocessor) -> None:
    result = pp._strip_sql_comments("SELECT # comment\nFROM")
    assert "FROM" in result


def test_decode_base64_candidates_valid(pp: ContentPreprocessor) -> None:
    import base64

    token = base64.b64encode(b"<script>alert(1)</script>").decode("ascii")
    result = pp._decode_base64_candidates(token)
    assert "<script>" in result


def test_decode_base64_candidates_leaves_0x_prefixed_hex_literal_untouched(
    pp: ContentPreprocessor,
) -> None:
    token = "0x2f6574632f706173737764"
    payload = f"LOAD_FILE({token})"
    result = pp._decode_base64_candidates(payload)
    assert result == payload


def test_is_hex_literal_rejects_bare_hex_pair_without_0x_prefix(
    pp: ContentPreprocessor,
) -> None:
    assert pp._is_hex_literal("deadbeefdeadbeefdeadbeef") is False


def test_decode_base64_candidates_preserves_bare_hex_token_not_valid_utf8(
    pp: ContentPreprocessor,
) -> None:
    token = "deadbeefdeadbeefdeadbeef"
    result = pp._decode_base64_candidates(token)
    assert result == token


def test_decode_base64_candidates_decodes_hex_lookalike_netcat_evasion_token(
    pp: ContentPreprocessor,
) -> None:
    token = "aCA5aCA0fE5De0A0aCA6"
    result = pp._decode_base64_candidates(token)
    assert result == "h 9h 4|NC{@4h :"
    assert _cmd_injection_detected(result)


def test_hex_lookalike_base64_evasion_survives_preprocessing_and_is_detected(
    pp: ContentPreprocessor,
) -> None:
    payload = "aCA5aCA0fE5De0A0aCA6"
    result = pp.preprocess(payload)
    assert _cmd_injection_detected(result)


def test_load_file_hex_literal_survives_preprocessing_uncorrupted(
    pp: ContentPreprocessor,
) -> None:
    payload = "LOAD_FILE(0x2f6574632f706173737764)"
    result = pp.preprocess(payload)
    assert "0x2f6574632f706173737764" in result


def test_decode_base64_candidates_returns_token_when_decode_fails(
    pp: ContentPreprocessor, monkeypatch: pytest.MonkeyPatch
) -> None:
    import base64

    def raise_value_error(*args: object, **kwargs: object) -> bytes:
        raise ValueError("forced decode failure")

    monkeypatch.setattr(base64, "b64decode", raise_value_error)

    payload = "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
    result = pp._decode_base64_candidates(payload)
    assert result == payload


def test_printable_ratio_of_empty_text_is_zero(pp: ContentPreprocessor) -> None:
    assert pp._printable_ratio("") == 0.0


def test_printable_ratio_of_all_printable_ascii_is_one(
    pp: ContentPreprocessor,
) -> None:
    assert pp._printable_ratio("hello world 123") == 1.0


def test_printable_ratio_excludes_control_characters(
    pp: ContentPreprocessor,
) -> None:
    assert pp._printable_ratio("ab\x01\x02") == 0.5


def test_printable_ratio_counts_non_ascii_letters_as_printable(
    pp: ContentPreprocessor,
) -> None:
    assert pp._printable_ratio("你好世界") == 1.0


def test_printable_ratio_of_mixed_ascii_and_cjk_is_one(
    pp: ContentPreprocessor,
) -> None:
    assert pp._printable_ratio("'; EXEC xp_cmdshell('whoami'); -- 你好") == 1.0


def test_replacement_char_ratio_of_empty_text_is_zero(pp: ContentPreprocessor) -> None:
    assert pp._replacement_char_ratio("") == 0.0


def test_replacement_char_ratio_counts_only_replacement_characters(
    pp: ContentPreprocessor,
) -> None:
    assert pp._replacement_char_ratio("ab��") == 0.5


def test_decode_base64_candidates_keeps_token_when_decoded_bytes_are_not_utf8(
    pp: ContentPreprocessor,
) -> None:
    import base64

    raw = bytes([0xFF, 0xFE, 0xFD, 0xFC] * 5)
    token = base64.b64encode(raw).decode("ascii")
    result = pp._decode_base64_candidates(token)
    assert result == token


def test_decode_base64_candidates_decodes_at_exact_printable_ratio_threshold(
    pp: ContentPreprocessor,
) -> None:
    import base64

    raw = b"A" * 10 + b"\x01" * 10
    token = base64.b64encode(raw).decode("ascii")
    result = pp._decode_base64_candidates(token)
    assert result == raw.decode("utf-8")


def test_decode_base64_candidates_keeps_token_just_below_printable_ratio_threshold(
    pp: ContentPreprocessor,
) -> None:
    import base64

    raw = b"A" * 9 + b"\x01" * 11
    token = base64.b64encode(raw).decode("ascii")
    result = pp._decode_base64_candidates(token)
    assert result == token


def test_decode_base64_candidates_decodes_valid_utf8_with_cyrillic_suffix(
    pp: ContentPreprocessor,
) -> None:
    import base64

    plaintext = "<script>alert(document.cookie)</script>АБВГДЕЖЗИЙ"
    token = base64.b64encode(plaintext.encode("utf-8")).decode("ascii")
    result = pp._decode_base64_candidates(token)
    assert result == plaintext
    assert "<script>" in result


def test_decode_base64_candidates_decodes_despite_single_invalid_trailing_byte(
    pp: ContentPreprocessor,
) -> None:
    import base64

    raw = b"<script>alert(document.cookie)</script>" + bytes([0x80])
    token = base64.b64encode(raw).decode("ascii")
    result = pp._decode_base64_candidates(token)
    assert "<script>alert(document.cookie)</script>" in result
    assert result != token


def test_hex_escape_value_error_path(pp: ContentPreprocessor) -> None:
    from unittest.mock import patch

    with patch("builtins.chr", side_effect=ValueError("invalid")):
        result = pp._decode_hex_escapes("\\x41")
    assert result == "\\x41"


def test_ldap_hex_escape_value_error_path(pp: ContentPreprocessor) -> None:
    from unittest.mock import patch

    with patch("builtins.chr", side_effect=ValueError("invalid")):
        result = pp._decode_ldap_hex_escapes("\\29")
    assert result == "\\29"


def test_unicode_escape_value_error_path(pp: ContentPreprocessor) -> None:
    from unittest.mock import patch

    with patch("builtins.chr", side_effect=ValueError("invalid")):
        result = pp._decode_unicode_escapes("\\u0041")
    assert result == "\\u0041"


def test_sql_between_token_comment_retained(
    pp: ContentPreprocessor,
) -> None:
    payload = "WHERE id=1/**/OR/**/x=2"
    result = pp.preprocess(payload)
    assert "/**/" in result
    assert "1or" not in result.lower()


def test_sql_lowercase_keyword_comment_retained(
    pp: ContentPreprocessor,
) -> None:
    payload = "sele/**/ct password fro/**/m users"
    result = pp.preprocess(payload)
    assert "/**/" in result
    assert "select" not in result.lower()


def test_sql_uppercase_keyword_comment_retained(
    pp: ContentPreprocessor,
) -> None:
    payload = "WHERE id=1 OR/**/x=2"
    result = pp.preprocess(payload)
    assert "/**/" in result
    assert "orx" not in result.lower()


def test_truncate_preserves_tail_content_after_attack_region(
    pp: ContentPreprocessor,
) -> None:
    pp2 = ContentPreprocessor(max_content_length=300, preserve_attack_patterns=True)
    attack = "<script>x</script>"
    safe_tail = "A" * 400
    payload = attack + safe_tail
    result = pp2.preprocess(payload)
    assert "<script" in result.lower()
    assert len(result) > len(attack)


def test_preprocess_keeps_the_xss_payload_after_a_line_comment_marker(
    pp: ContentPreprocessor,
) -> None:
    result = pp.preprocess("x-- <script>alert(1)</script>")
    assert result == "x-- <script>alert(1)</script>"


def test_preprocess_keeps_the_command_substitution_after_a_marker(
    pp: ContentPreprocessor,
) -> None:
    result = pp.preprocess("a--$(whoami)")
    assert result == "a--$(whoami)"


def test_preprocess_keeps_the_union_select_after_a_marker(
    pp: ContentPreprocessor,
) -> None:
    result = pp.preprocess("q=1-- OR 1=1 UNION SELECT password")
    assert result == "q=1-- OR 1=1 UNION SELECT password"


def test_preprocess_keeps_a_trailing_line_comment_marker(
    pp: ContentPreprocessor,
) -> None:
    result = pp.preprocess("' OR 1=1 --")
    assert result == "' OR 1=1 --"


def test_preprocess_keeps_the_double_dash_of_a_cli_flag(
    pp: ContentPreprocessor,
) -> None:
    result = pp.preprocess("`docker run --rm -it alpine sh`")
    assert result == "`docker run --rm -it alpine sh`"


def test_strip_sql_comments_standalone_block_comment_preserves_interior(
    pp: ContentPreprocessor,
) -> None:
    result = pp._strip_sql_comments("x/* DROP TABLE users */")
    assert "DROP TABLE users" in result


def test_strip_sql_comments_leading_block_comment_preserves_trailing_payload(
    pp: ContentPreprocessor,
) -> None:
    result = pp._strip_sql_comments("/*<script>alert(1)</script>*/")
    assert result.strip() == "<script>alert(1)</script>"


def test_strip_sql_comments_empty_block_comment_does_not_leak_none_literal(
    pp: ContentPreprocessor,
) -> None:
    result = pp._strip_sql_comments("/**/ tail")
    assert "None" not in result
    assert "tail" in result


def test_cli_double_dash_flags_are_not_deleted(pp: ContentPreprocessor) -> None:
    result = pp.preprocess("docker run --rm -it alpine sh")
    for word in ("docker", "run", "alpine", "sh"):
        assert word in result


def test_double_slash_in_url_is_left_untouched(pp: ContentPreprocessor) -> None:
    result = pp.preprocess("see http://example.com//path for the doc")
    assert result == "see http://example.com//path for the doc"


def test_hash_fragment_words_survive_preprocessing(
    pp: ContentPreprocessor,
) -> None:
    result = pp.preprocess("visit http://example.com/page#section for details")
    assert "section" in result
    assert "details" in result


def test_block_comment_in_prose_preserves_interior_words(
    pp: ContentPreprocessor,
) -> None:
    result = pp.preprocess("the file has a /* TODO */ marker inside it")
    for word in ("TODO", "marker", "inside"):
        assert word in result


def test_decode_percent_u_escapes_directly(pp: ContentPreprocessor) -> None:
    assert pp._decode_percent_u_escapes("%u002e%u002e") == ".."


def test_decode_percent_u_escapes_value_error_path(pp: ContentPreprocessor) -> None:
    from unittest.mock import patch

    with patch("builtins.chr", side_effect=ValueError("invalid")):
        result = pp._decode_percent_u_escapes("%u002e")
    assert result == "%u002e"


def test_lenient_overlong_utf8_decode_passes_through_ascii(
    pp: ContentPreprocessor,
) -> None:
    assert pp._lenient_overlong_utf8_decode(b"A") == "A"


def test_lenient_overlong_utf8_decode_two_byte_overlong_slash(
    pp: ContentPreprocessor,
) -> None:
    assert pp._lenient_overlong_utf8_decode(bytes([0xC0, 0xAF])) == "/"


def test_lenient_overlong_utf8_decode_truncated_lead_byte_is_dropped(
    pp: ContentPreprocessor,
) -> None:
    assert pp._lenient_overlong_utf8_decode(bytes([0xC0])) == ""


def test_lenient_overlong_utf8_decode_bad_first_continuation_is_dropped(
    pp: ContentPreprocessor,
) -> None:
    assert pp._lenient_overlong_utf8_decode(bytes([0xC0, 0x2F])) == "/"


def test_lenient_overlong_utf8_decode_three_byte_overlong_slash(
    pp: ContentPreprocessor,
) -> None:
    assert pp._lenient_overlong_utf8_decode(bytes([0xE0, 0x80, 0xAF])) == "/"


def test_lenient_overlong_utf8_decode_bad_trailing_continuation_is_dropped(
    pp: ContentPreprocessor,
) -> None:
    assert pp._lenient_overlong_utf8_decode(bytes([0xE0, 0x80, 0x2F])) == "/"


def test_lenient_overlong_utf8_decode_four_byte_overlong_slash(
    pp: ContentPreprocessor,
) -> None:
    assert pp._lenient_overlong_utf8_decode(bytes([0xF0, 0x80, 0x80, 0xAF])) == "/"


def test_decode_overlong_utf8_percent_runs_leaves_valid_utf8_untouched(
    pp: ContentPreprocessor,
) -> None:
    assert pp._decode_overlong_utf8_percent_runs("%c3%a9") == "%c3%a9"


def test_decode_overlong_utf8_percent_runs_decodes_invalid_overlong_run(
    pp: ContentPreprocessor,
) -> None:
    assert pp._decode_overlong_utf8_percent_runs("%c0%af") == "/"


def test_percent_u_iis_unicode_dot_pair_decodes_to_literal_dots(
    pp: ContentPreprocessor,
) -> None:
    result = pp.preprocess("%u002e%u002e%2f")
    assert result == "../"


def test_percent_u_division_slash_renormalizes_to_ascii_slash(
    pp: ContentPreprocessor,
) -> None:
    result = pp.preprocess("%u002e%u002e%u2215")
    assert result == "../"


def test_percent_u_fullwidth_solidus_renormalizes_to_ascii_slash(
    pp: ContentPreprocessor,
) -> None:
    result = pp.preprocess("..%uff0f")
    assert result == "../"


def test_four_byte_overlong_utf8_slash_decodes_through_preprocess(
    pp: ContentPreprocessor,
) -> None:
    result = pp.preprocess("..%f0%80%80%af")
    assert result == "../"


def test_valid_multibyte_percent_encoded_utf8_is_unaffected(
    pp: ContentPreprocessor,
) -> None:
    result = pp.preprocess("caf%c3%a9")
    assert result == "café"
