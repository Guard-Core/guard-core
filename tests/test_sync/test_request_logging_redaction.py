import json
import math
import multiprocessing as mp
import resource
import time
from urllib.parse import quote

import pytest

from guard_core.sync._utils.pair_hidden_assign import (
    _close_dangling_quote_in_continuation,
    _open_quote_at_end,
    _redact_adjacent_sensitive_value,
    _rescan_decoded_run,
)
from guard_core.sync._utils.pair_value_scan import (
    _has_undecoded_percent_escape,
    _looks_like_json_start,
    _redact_embedded_json_value,
)
from guard_core.sync._utils.request_logging import (
    _redact_pairs_in_text,
    redact_blob_for_display,
    redact_url_for_display,
)

_XSS = "<script>alert(1)</script>"
_DEFAULT_SENSITIVE = frozenset({"password", "token"})


def _encode_n(text: str, rounds: int) -> str:
    encoded = text
    for _ in range(rounds):
        encoded = quote(encoded, safe="")
    return encoded


def _encode_name_n_rounds(name: str, rounds: int) -> str:
    encoded = "".join(f"%{ord(c):02X}" for c in name)
    for _ in range(rounds - 1):
        encoded = quote(encoded, safe="")
    return encoded


def test_redact_blob_for_display_comma_separated_pair_redacts_secret() -> None:
    result = redact_blob_for_display(
        f"a=1,password=SECRET-COMMA {_XSS}", frozenset(), frozenset()
    )
    assert "SECRET-COMMA" not in result
    assert result == f"a=1,password=[REDACTED]{_XSS}"


def test_redact_blob_for_display_whitespace_before_equals_redacts_secret() -> None:
    result = redact_blob_for_display(
        f"password =SECRET-WS-BEFORE {_XSS}", frozenset(), frozenset()
    )
    assert "SECRET-WS-BEFORE" not in result
    assert result == f"password =[REDACTED]{_XSS}"


def test_redact_blob_for_display_whitespace_both_sides_equals_redacts_secret() -> None:
    result = redact_blob_for_display(
        f"password = SECRET-WS-BOTH {_XSS}", frozenset(), frozenset()
    )
    assert "SECRET-WS-BOTH" not in result
    assert result == f"password = [REDACTED]{_XSS}"


def test_redact_blob_for_display_tab_before_equals_redacts_secret() -> None:
    result = redact_blob_for_display(
        "password\t=SECRET-TAB-BEFORE", frozenset(), frozenset()
    )
    assert "SECRET-TAB-BEFORE" not in result
    assert result == "password\t=[REDACTED]"


def test_redact_blob_for_display_colon_assignment_redacts_secret() -> None:
    result = redact_blob_for_display("password: SECRET-COLON", frozenset(), frozenset())
    assert "SECRET-COLON" not in result
    assert result == "password: [REDACTED]"


def test_redact_blob_for_display_double_equals_redacts_secret() -> None:
    result = redact_blob_for_display(
        "password==SECRET-DOUBLE-EQ", frozenset(), frozenset()
    )
    assert "SECRET-DOUBLE-EQ" not in result
    assert result == "password==[REDACTED]"


def test_redact_pairs_in_text_double_equals_before_quoted_value_redacts_secret() -> (
    None
):
    result = _redact_pairs_in_text('password=="SECRET-DBLQ"', frozenset({"password"}))
    assert "SECRET-DBLQ" not in result
    assert result == 'password=="[REDACTED]"'


def test_redact_pairs_in_text_unquoted_value_stops_at_unmatched_quote() -> None:
    result = _redact_pairs_in_text('{"note": "token=SECRET"}', frozenset({"token"}))
    assert "SECRET" not in result
    assert result == '{"note": "token=[REDACTED]"}'


def test_redact_pairs_in_text_percent_encoded_whole_json_blob_redacts_secret() -> None:
    blob = json.dumps({"password": "SECRET-WHOLEJSON"})
    encoded = quote(blob, safe="")
    result = _redact_pairs_in_text(encoded, frozenset(), frozenset({"password"}))
    assert "SECRET-WHOLEJSON" not in result


def test_redact_blob_for_display_space_inside_secret_value_redacted() -> None:
    result = redact_blob_for_display(
        f"password=my SECRET-INNER-SPACE value {_XSS}", frozenset(), frozenset()
    )
    assert "SECRET-INNER-SPACE" not in result
    assert result == f"password=[REDACTED]{_XSS}"


def test_redact_blob_for_display_middle_of_multi_pair_blob_redacts_secret() -> None:
    result = redact_blob_for_display(
        "a=1 password=SECRET-MID b=2", frozenset(), frozenset()
    )
    assert "SECRET-MID" not in result
    assert result == "a=1 password=[REDACTED] b=2"


def test_redact_blob_for_display_nested_quoted_pair_redacts_secret() -> None:
    result = redact_blob_for_display(
        'filename="password=SECRET-QUOTED"', frozenset(), frozenset()
    )
    assert "SECRET-QUOTED" not in result
    assert result == 'filename="password=[REDACTED]"'


def test_redact_blob_for_display_xml_attribute_redacts_secret() -> None:
    result = redact_blob_for_display(
        '<user password="SECRET-XML-ATTR"/>', frozenset(), frozenset()
    )
    assert "SECRET-XML-ATTR" not in result
    assert result == '<user password="[REDACTED]"/>'


def test_redact_blob_for_display_nested_pair_without_quotes_redacts_secret() -> None:
    result = redact_blob_for_display(
        "data=password=SECRET-NESTED", frozenset(), frozenset()
    )
    assert "SECRET-NESTED" not in result
    assert result == "data=password=[REDACTED]"


def test_redact_blob_for_display_percent_encoded_equals_redacts_secret() -> None:
    result = redact_blob_for_display(
        "password%3DSECRET-PCT-EQ", frozenset(), frozenset()
    )
    assert "SECRET-PCT-EQ" not in result


def test_redact_blob_for_display_pct_encoded_ampersand_smuggle_redacts_secret() -> None:
    result = redact_blob_for_display(
        "a%3D1%26password%3DSECRET-PCT-AMP%26y%3D2", frozenset(), frozenset()
    )
    assert "SECRET-PCT-AMP" not in result


def test_redact_blob_for_display_comma_list_of_benign_values_unchanged() -> None:
    assert redact_blob_for_display("ids=1,2,3", frozenset(), frozenset()) == "ids=1,2,3"


def test_redact_blob_for_display_space_around_equals_non_sensitive_unchanged() -> None:
    result = redact_blob_for_display("note = value", frozenset(), frozenset())
    assert result == "note = value"


def test_redact_url_for_display_comma_separated_query_pair_redacts_secret() -> None:
    result = redact_url_for_display(
        "/resource?a=1,token=SECRET-URL-COMMA", frozenset(), frozenset()
    )
    assert "SECRET-URL-COMMA" not in result
    assert result == "/resource?a=1,token=[REDACTED]"


def test_redact_url_for_display_pct_encoded_space_in_name_redacts_secret() -> None:
    result = redact_url_for_display(
        "/resource?token%20=SECRET-URL-PCTWS", frozenset(), frozenset()
    )
    assert "SECRET-URL-PCTWS" not in result
    assert result == "/resource?token%20=[REDACTED]"


def test_redact_pairs_in_text_comma_separated_pair_redacts_secret() -> None:
    result = _redact_pairs_in_text("a=1,token=SECRET-QS-COMMA", _DEFAULT_SENSITIVE)
    assert "SECRET-QS-COMMA" not in result
    assert result == "a=1,token=[REDACTED]"


def test_redact_pairs_in_text_benign_comma_list_unchanged() -> None:
    result = _redact_pairs_in_text("ids=1,2,3", _DEFAULT_SENSITIVE)
    assert result == "ids=1,2,3"


def test_redact_pairs_in_text_byte_identical_when_nothing_sensitive() -> None:
    text = "a=1&b=2;c=3?d=4 e=5\tf=6"
    assert _redact_pairs_in_text(text, _DEFAULT_SENSITIVE) == text


def test_redact_blob_for_display_dangling_hidden_pair_before_hard_separator() -> None:
    result = redact_blob_for_display("password%3D&next=1", frozenset(), frozenset())
    assert result == "[REDACTED]&next=1"


def test_redact_blob_for_display_dangling_hidden_pair_at_end_of_string() -> None:
    result = redact_blob_for_display("password%3D", frozenset(), frozenset())
    assert result == "[REDACTED]"


def test_redact_adjacent_sensitive_value_returns_none_at_end_of_string() -> None:
    assert _redact_adjacent_sensitive_value("password", 8) is None


def test_redact_adjacent_sensitive_value_returns_none_before_hard_separator() -> None:
    assert _redact_adjacent_sensitive_value("password&next=1", 8) is None


def test_looks_like_json_start_false_when_position_out_of_bounds() -> None:
    assert _looks_like_json_start("abc", 10) is False


def test_open_quote_at_end_returns_empty_for_marker_with_no_prefix() -> None:
    assert _open_quote_at_end("[REDACTED]") == ""


def test_close_dangling_quote_without_continuation_returns_unchanged() -> None:
    assert _close_dangling_quote_in_continuation('"[REDACTED]', "") == (
        '"[REDACTED]',
        0,
    )


def test_close_dangling_quote_in_continuation_consumes_to_end_when_never_closed() -> (
    None
):
    tail = "tail with no quote"
    result = _close_dangling_quote_in_continuation('"[REDACTED]', tail)
    assert result == ('"[REDACTED]', len(tail))


def test_rescan_decoded_run_dangling_with_no_adjacent_value_returns_local_only() -> (
    None
):
    result = _rescan_decoded_run(
        "password=", "&next=1", frozenset({"password"}), frozenset(), 32
    )
    assert result == ("password=[REDACTED]", 0)


def test_rescan_decoded_run_json_like_prefix_falls_through_when_invalid_json() -> None:
    result = _rescan_decoded_run(
        "{password=hunter2", "", frozenset({"password"}), frozenset(), 32
    )
    assert result == ("{password=[REDACTED]", 0)


def test_looks_like_json_start_false_for_plain_non_percent_character() -> None:
    assert _looks_like_json_start("xyz", 0) is False


def test_redact_embedded_json_value_none_for_scalar_json() -> None:
    result = _redact_embedded_json_value(
        '"just a string"', frozenset(), frozenset(), 32
    )
    assert result is None


def test_redact_blob_for_display_double_quoted_name_and_value_redacts_secret() -> None:
    result = redact_blob_for_display('"password":"SECRET-DQ"', frozenset(), frozenset())
    assert "SECRET-DQ" not in result
    assert result == '"password":"[REDACTED]"'


def test_redact_blob_for_display_single_quoted_name_and_value_redacts_secret() -> None:
    result = redact_blob_for_display(
        "'password': 'SECRET-SQ'", frozenset(), frozenset()
    )
    assert "SECRET-SQ" not in result
    assert result == "'password': '[REDACTED]'"


def test_redact_blob_for_display_double_quoted_name_unquoted_value_redacts_secret() -> (
    None
):
    result = redact_blob_for_display(
        '"password": SECRET-YAML-STYLE', frozenset(), frozenset()
    )
    assert "SECRET-YAML-STYLE" not in result
    assert result == '"password": [REDACTED]'


def test_redact_blob_for_display_quoted_name_header_value_with_trailing_xss() -> None:
    result = redact_blob_for_display(
        f'"password":"SECRET-XSS-TAIL" {_XSS}', frozenset(), frozenset()
    )
    assert "SECRET-XSS-TAIL" not in result
    assert result == f'"password":"[REDACTED]" {_XSS}'


def test_redact_blob_for_display_oversized_json_quoted_name_redacts_secret() -> None:
    padding = "a" * 16400
    text = f'note={{"padding":"{padding}","password":"SECRET-OVERSIZED"}}'
    result = redact_blob_for_display(text, frozenset(), frozenset())
    assert "SECRET-OVERSIZED" not in result
    assert '"password":"[REDACTED]"' in result


def test_redact_blob_for_display_invalid_json_header_value_with_quoted_name() -> None:
    text = '"password":"SECRET-INVALID-JSON but not valid json at all'
    result = redact_blob_for_display(text, frozenset(), frozenset())
    assert "SECRET-INVALID-JSON" not in result


def test_redact_pairs_in_text_name_encoded_four_times_stays_fail_closed() -> None:
    encoded_name = _encode_name_n_rounds("password", 4)
    result = _redact_pairs_in_text(
        f"{encoded_name}=SECRET-ENC4", frozenset({"password"})
    )
    assert "SECRET-ENC4" not in result
    assert result == f"{encoded_name}=[REDACTED]"


def test_redact_pairs_in_text_name_encoded_five_times_stays_fail_closed() -> None:
    encoded_name = _encode_name_n_rounds("password", 5)
    result = _redact_pairs_in_text(
        f"{encoded_name}=SECRET-ENC5", frozenset({"password"})
    )
    assert "SECRET-ENC5" not in result
    assert result == f"{encoded_name}=[REDACTED]"


def test_bounded_decode_of_four_round_name_leaves_percent_escape() -> None:
    from guard_core.sync._utils.pair_redaction import _bounded_percent_decode

    encoded_name = _encode_name_n_rounds("password", 4)
    decoded = _bounded_percent_decode(encoded_name)
    assert _has_undecoded_percent_escape(decoded) is True


def test_redact_blob_for_display_bare_percent_name_stays_byte_identical() -> None:
    text = "5%off=SAVE10"
    assert redact_blob_for_display(text, frozenset(), frozenset()) == text


def test_has_undecoded_percent_escape_false_for_bare_percent_without_hex_digits() -> (
    None
):
    assert _has_undecoded_percent_escape("5%off") is False
    assert _has_undecoded_percent_escape("50%2X") is False


def test_has_undecoded_percent_escape_true_for_valid_percent_escape() -> None:
    assert _has_undecoded_percent_escape("50%2f") is True


def test_redact_url_for_display_doubled_triple_encoded_equals_redacts_secret() -> None:
    secret = "SECRET-DEFECT74-DOUBLE-EQ"
    url = (
        f"https://test/resource?x%25253D1;PASSWORD%25253D%25253D "
        f"'{secret} {_XSS}';y%25253D2"
    )
    result = redact_url_for_display(url, frozenset(), frozenset())
    assert secret not in result
    assert result == (
        "https://test/resource?x%25253D1;[REDACTED] '[REDACTED]';y%25253D2"
    )


def test_redact_url_for_display_colon_space_inside_json_leaf_matrix_param() -> None:
    secret = "SECRET-DEFECT74-COLON-SPACE"
    path = f'/resource;{{"note": "x=1%2CAcCeSs_tOkEn: \\"{secret} {_XSS}\\"%2Cy=2"}}'
    url = f"https://test{path}"
    result = redact_url_for_display(url, frozenset(), frozenset())
    assert secret not in result
    assert result == (
        "https://test/resource;%7B%22note%22%3A%22x%3D1%2CAcCeSs_tOkEn"
        "%3A%20%5C%22%5BREDACTED%5D%5C%22%2Cy%3D2%22%7D"
    )


def test_redact_url_for_display_tab_before_triple_encoded_equals_redacts_secret() -> (
    None
):
    secret = "SECRET-DEFECT74-TAB-EQ"
    url = (
        f"https://test/resource?data%25253DX-CuStOm-sEcReT-HeAdEr\t%25253D"
        f"'{secret} {_XSS}'\x0bx%25253D1\x0by%25253D2"
    )
    result = redact_url_for_display(
        url, frozenset({"x-custom-secret-header"}), frozenset()
    )
    assert secret not in result
    assert result == (
        "https://test/resource?data=X-CuStOm-sEcReT-HeAdEr\t=[REDACTED]"
        "'[REDACTED]'\x0bx%25253D1\x0by%25253D2"
    )


_BUDGET_LARGE_REPEATS = 100000
_BUDGET_SMALL_REPEATS = 50000
_BUDGET_MAX_DURATION_SECONDS = 0.3
_BUDGET_ESCAPE_RUN_MAX_DURATION_SECONDS = 1.0
_BUDGET_MAX_RATIO = 3.0
_BUDGET_CPU_DEADLINE_SECONDS = 10
_STALLED_CHILD_WALL_SECONDS = 120.0
_BUDGET_SAMPLE_COUNT = 5


def _time_one_redact_blob(text: str) -> float:
    start = time.process_time()
    redact_blob_for_display(text, frozenset(), frozenset())
    return time.process_time() - start


_BUDGET_ADVERSARIAL_UNITS = ("a=", "\\\\t", "\\N{TAB}", "\\u{9}", 'password\t:"')


def _limit_child_cpu_to_the_deadline() -> None:
    _soft, hard = resource.getrlimit(resource.RLIMIT_CPU)
    soft = math.ceil(time.process_time()) + _BUDGET_CPU_DEADLINE_SECONDS
    if hard != resource.RLIM_INFINITY:
        soft = min(soft, hard)
    resource.setrlimit(resource.RLIMIT_CPU, (soft, hard))


def _redact_blob_min_duration_child(
    repeats: int, q: "mp.Queue[float]", unit: str = "a="
) -> None:
    _limit_child_cpu_to_the_deadline()
    text = unit * repeats
    durations = [_time_one_redact_blob(text) for _ in range(_BUDGET_SAMPLE_COUNT)]
    q.put(min(durations))


def _measure_redact_blob_min_duration(repeats: int, unit: str = "a=") -> float | None:
    ctx = mp.get_context("forkserver")
    q: mp.Queue[float] = ctx.Queue()
    proc = ctx.Process(target=_redact_blob_min_duration_child, args=(repeats, q, unit))
    proc.start()
    # The child's CPU limit is the deadline; this catches a child that stopped running.
    proc.join(_STALLED_CHILD_WALL_SECONDS)
    if proc.is_alive():
        proc.terminate()
        proc.join()
        return None
    return q.get() if not q.empty() else None


def _assert_redact_blob_adversarial_pairs_stay_linear() -> None:
    large_duration = _measure_redact_blob_min_duration(_BUDGET_LARGE_REPEATS)
    assert large_duration is not None, (
        f"redact_blob_for_display did not return within "
        f"{_BUDGET_CPU_DEADLINE_SECONDS} CPU seconds at repeats={_BUDGET_LARGE_REPEATS}"
    )
    assert large_duration < _BUDGET_MAX_DURATION_SECONDS, (
        f"redact_blob_for_display took {large_duration:.4f}s for "
        f"repeats={_BUDGET_LARGE_REPEATS}, over the "
        f"{_BUDGET_MAX_DURATION_SECONDS}s budget"
    )

    small_duration = _measure_redact_blob_min_duration(_BUDGET_SMALL_REPEATS)
    assert small_duration is not None, (
        f"redact_blob_for_display did not return within "
        f"{_BUDGET_CPU_DEADLINE_SECONDS} CPU seconds at repeats={_BUDGET_SMALL_REPEATS}"
    )
    assert small_duration > 0.001, (
        f"redact_blob_for_display took {small_duration:.4f}s for "
        f"repeats={_BUDGET_SMALL_REPEATS}, too fast to measure a growth ratio"
    )
    ratio = large_duration / small_duration
    assert ratio < _BUDGET_MAX_RATIO, (
        f"redact_blob_for_display CPU-time ratio {ratio:.2f} between repeats="
        f"{_BUDGET_LARGE_REPEATS} ({large_duration:.4f}s) and repeats="
        f"{_BUDGET_SMALL_REPEATS} ({small_duration:.4f}s) is not linear"
    )


def test_redact_blob_for_display_adversarial_pairs_stay_linear() -> None:
    try:
        _assert_redact_blob_adversarial_pairs_stay_linear()
    except AssertionError:
        _assert_redact_blob_adversarial_pairs_stay_linear()


@pytest.mark.parametrize("unit", _BUDGET_ADVERSARIAL_UNITS[1:])
def test_redact_blob_for_display_escape_runs_stay_linear(unit: str) -> None:
    large_repeats = 200_000 // len(unit)
    small_repeats = large_repeats // 2
    large = _measure_redact_blob_min_duration(large_repeats, unit)
    small = _measure_redact_blob_min_duration(small_repeats, unit)
    assert large is not None and small is not None, unit
    assert large < _BUDGET_ESCAPE_RUN_MAX_DURATION_SECONDS, (unit, large)
    assert small > 0.0005, (unit, small)
    assert large / small < _BUDGET_MAX_RATIO, (unit, large, small)
