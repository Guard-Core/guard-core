import json
import random
import time
from urllib.parse import quote

import pytest

from guard_core.sync._utils.logging_utils import _redact_sensitive_json
from guard_core.sync._utils.request_logging import (
    redact_blob_for_display,
    redact_url_for_display,
)

_SEED = 20260903
_MAX_CASES = 600
_TIME_BUDGET_SECONDS = 20.0

_NAME_CASINGS = ["password", "Password", "PASSWORD"]
_WS_COMBOS = [("", ""), (" ", ""), ("", " "), (" ", " "), ("\t", "\t")]
_ASSIGN_CHARS = ["=", ":"]
_SEPARATORS = ["&", ";", ",", "?", "|", " ", "\t", "\r", "\n", "\r\n", " "]
_QUOTINGS = ["none", "double", "single"]
_WRAPPERS = [
    "bare",
    "nested_data",
    "filename_quoted",
    "json_leaf",
    "xml_text",
    "xml_attr",
]
_ENCODINGS = [
    (0, "whole"),
    (1, "whole"),
    (2, "whole"),
    (3, "whole"),
    (4, "whole"),
    (5, "whole"),
]
_ENCODINGS += [(r, t) for r in (1, 2, 3) for t in ("eq", "sep")]

_NAME_QUOTINGS = ["none", "double", "single"]

_SENSITIVE = frozenset({"password"})
_BENIGN_NAME = "note"
_TAIL = "TAILMARKER"


def _percent_encode_n(text: str, rounds: int) -> str:
    encoded = text
    for _ in range(rounds):
        encoded = quote(encoded, safe="")
    return encoded


def _quote_value(value: str, quoting: str) -> str:
    if quoting == "double":
        return f'"{value}"'
    if quoting == "single":
        return f"'{value}'"
    return value


def _quote_name(name: str, name_quoting: str) -> str:
    if name_quoting == "double":
        return f'"{name}"'
    if name_quoting == "single":
        return f"'{name}'"
    return name


def _make_pair(
    name: str,
    ws_pre: str,
    ws_post: str,
    assign_char: str,
    quoting: str,
    value: str,
    enc_rounds: int,
    enc_target: str,
    name_quoting: str = "none",
) -> str:
    quoted_name = _quote_name(name, name_quoting)
    quoted_value = _quote_value(value, quoting)
    if enc_rounds == 0 or enc_target == "sep":
        return f"{quoted_name}{ws_pre}{assign_char}{ws_post}{quoted_value}"
    if enc_target == "whole":
        return _percent_encode_n(
            f"{quoted_name}{ws_pre}{assign_char}{ws_post}{quoted_value}", enc_rounds
        )
    encoded_assign = _percent_encode_n(assign_char, enc_rounds)
    return f"{quoted_name}{ws_pre}{encoded_assign}{ws_post}{quoted_value}"


def _make_separator(separator: str, enc_rounds: int, enc_target: str) -> str:
    if enc_target == "sep" and enc_rounds > 0:
        return _percent_encode_n(separator, enc_rounds)
    return separator


def _eligible_for_url_display(
    ws_pre: str, ws_post: str, separator: str, wrapper: str
) -> bool:
    if wrapper not in ("bare", "nested_data"):
        return False
    control_chars = "\t\r\n"
    return not any(ch in control_chars for ch in ws_pre + ws_post + separator)


def _wrap(wrapper: str, pair: str) -> str:
    if wrapper == "bare":
        return pair
    if wrapper == "nested_data":
        return f"data={pair}"
    if wrapper == "filename_quoted":
        return f'filename="{pair}"'
    if wrapper == "xml_text":
        return f"<note>{pair}</note>"
    if wrapper == "xml_attr":
        return f"<user {pair}/>"
    raise AssertionError(f"unhandled wrapper {wrapper!r}")


def _render_and_check(
    name: str,
    ws_pre: str,
    ws_post: str,
    assign_char: str,
    separator: str,
    quoting: str,
    wrapper: str,
    enc_rounds: int,
    enc_target: str,
    marker: str,
    name_quoting: str = "none",
) -> str:
    if wrapper == "json_leaf":
        quoted_name = _quote_name(name, name_quoting)
        quoted_marker = _quote_value(marker, quoting)
        pair = f"{quoted_name}{ws_pre}{assign_char}{ws_post}{quoted_marker}"
        result = _redact_sensitive_json({"note": pair}, frozenset(), _SENSITIVE, 32)
        assert isinstance(result, dict)
        return str(result["note"])

    pair = _make_pair(
        name,
        ws_pre,
        ws_post,
        assign_char,
        quoting,
        marker,
        enc_rounds,
        enc_target,
        name_quoting,
    )
    body = _wrap(wrapper, pair)
    sep_text = _make_separator(separator, enc_rounds, enc_target)
    text = f"{body}{sep_text}{_TAIL}"

    if _eligible_for_url_display(ws_pre, ws_post, separator, wrapper):
        return redact_url_for_display(f"/r?{text}", frozenset(), frozenset())
    return redact_blob_for_display(text, frozenset(), frozenset())


def _assert_secret_absent_case(
    name: str,
    ws_pre: str,
    ws_post: str,
    assign_char: str,
    separator: str,
    quoting: str,
    wrapper: str,
    enc_rounds: int,
    enc_target: str,
    name_quoting: str = "none",
) -> None:
    secret = "SEC RET-" + "".join(
        str(hash((name, ws_pre, ws_post, assign_char, separator, quoting, wrapper)))[
            -6:
        ]
    )
    result = _render_and_check(
        name,
        ws_pre,
        ws_post,
        assign_char,
        separator,
        quoting,
        wrapper,
        enc_rounds,
        enc_target,
        secret,
        name_quoting,
    )
    assert secret not in result, (
        f"secret leaked for case name={name!r} ws=({ws_pre!r},{ws_post!r}) "
        f"assign={assign_char!r} sep={separator!r} quoting={quoting} "
        f"wrapper={wrapper} enc=({enc_rounds},{enc_target}) "
        f"name_quoting={name_quoting}: {result!r}"
    )


def _assert_benign_twin_byte_identical(
    ws_pre: str,
    ws_post: str,
    assign_char: str,
    separator: str,
    quoting: str,
    wrapper: str,
    enc_rounds: int,
    enc_target: str,
    name_quoting: str = "none",
) -> None:
    benign_value = "benignvalue"
    if wrapper == "json_leaf":
        quoted_name = _quote_name(_BENIGN_NAME, name_quoting)
        quoted_benign = _quote_value(benign_value, quoting)
        pair = f"{quoted_name}{ws_pre}{assign_char}{ws_post}{quoted_benign}"
        result = _redact_sensitive_json({"note": pair}, frozenset(), _SENSITIVE, 32)
        assert isinstance(result, dict)
        assert result["note"] == pair
        return

    pair = _make_pair(
        _BENIGN_NAME,
        ws_pre,
        ws_post,
        assign_char,
        quoting,
        benign_value,
        enc_rounds,
        enc_target,
        name_quoting,
    )
    body = _wrap(wrapper, pair)
    sep_text = _make_separator(separator, enc_rounds, enc_target)
    text = f"{body}{sep_text}{_TAIL}"

    if _eligible_for_url_display(ws_pre, ws_post, separator, wrapper):
        url = f"/r?{text}"
        assert redact_url_for_display(url, frozenset(), frozenset()) == url
        return
    assert redact_blob_for_display(text, frozenset(), frozenset()) == text


_Case = tuple[str, str, str, str, str, str, str, int, str, str]


def _one_axis_sweep_cases() -> list[_Case]:
    baseline = ("password", "", "", "=", "&", "none", "bare", 0, "whole", "none")
    cases = [baseline]
    for value in _NAME_CASINGS:
        cases.append((value, "", "", "=", "&", "none", "bare", 0, "whole", "none"))
    for ws_pre, ws_post in _WS_COMBOS:
        cases.append(
            ("password", ws_pre, ws_post, "=", "&", "none", "bare", 0, "whole", "none")
        )
    for value in _ASSIGN_CHARS:
        cases.append(
            ("password", "", "", value, "&", "none", "bare", 0, "whole", "none")
        )
    for value in _SEPARATORS:
        cases.append(
            ("password", "", "", "=", value, "none", "bare", 0, "whole", "none")
        )
    for value in _QUOTINGS:
        cases.append(("password", "", "", "=", "&", value, "bare", 0, "whole", "none"))
    for value in _WRAPPERS:
        cases.append(("password", "", "", "=", "&", "none", value, 0, "whole", "none"))
    for rounds, target in _ENCODINGS:
        cases.append(
            ("password", "", "", "=", "&", "none", "bare", rounds, target, "none")
        )
    for value in _NAME_QUOTINGS:
        cases.append(("password", "", "", "=", "&", "none", "bare", 0, "whole", value))
    return cases


def _random_sample_cases(count: int) -> list[_Case]:
    rng = random.Random(_SEED)
    cases = []
    for _ in range(count):
        name = rng.choice(_NAME_CASINGS)
        ws_pre, ws_post = rng.choice(_WS_COMBOS)
        assign_char = rng.choice(_ASSIGN_CHARS)
        separator = rng.choice(_SEPARATORS)
        quoting = rng.choice(_QUOTINGS)
        wrapper = rng.choice(_WRAPPERS)
        rounds, target = rng.choice(_ENCODINGS) if wrapper == "bare" else (0, "whole")
        name_quoting = rng.choice(_NAME_QUOTINGS) if wrapper != "json_leaf" else "none"
        cases.append(
            (
                name,
                ws_pre,
                ws_post,
                assign_char,
                separator,
                quoting,
                wrapper,
                rounds,
                target,
                name_quoting,
            )
        )
    return cases


_ALL_CASES = _one_axis_sweep_cases() + _random_sample_cases(
    _MAX_CASES - len(_one_axis_sweep_cases())
)


def test_case_count_and_axis_coverage_are_within_budget() -> None:
    assert len(_ALL_CASES) <= _MAX_CASES
    assert len(_ALL_CASES) >= 200


@pytest.mark.parametrize(
    "case", _ALL_CASES, ids=[f"case_{i}" for i in range(len(_ALL_CASES))]
)
def test_sensitive_pair_grammar_redacts_secret_and_preserves_benign_bytes(
    case: _Case,
) -> None:
    (
        name,
        ws_pre,
        ws_post,
        assign_char,
        separator,
        quoting,
        wrapper,
        rounds,
        target,
        name_quoting,
    ) = case
    _assert_secret_absent_case(
        name,
        ws_pre,
        ws_post,
        assign_char,
        separator,
        quoting,
        wrapper,
        rounds,
        target,
        name_quoting,
    )
    _assert_benign_twin_byte_identical(
        ws_pre,
        ws_post,
        assign_char,
        separator,
        quoting,
        wrapper,
        rounds,
        target,
        name_quoting,
    )


_AssignToken = tuple[str, int]
_AssignRunSpec = tuple[_AssignToken, ...]

_ASSIGN_RUN_SPECS: list[_AssignRunSpec] = [
    (("=", 0),),
    ((":", 0),),
    (("=", 1),),
    (("=", 2),),
    (("=", 3),),
    (("=", 0), ("=", 0)),
    ((":", 0), (":", 0)),
    (("=", 0), ("=", 1)),
    (("=", 1), ("=", 0)),
    (("=", 2), ("=", 3)),
    (("=", 0), (":", 0)),
    (("=", 0), ("=", 0), ("=", 0)),
    (("=", 1), ("=", 2), ("=", 3)),
    (("=", 3), ("=", 0), ("=", 1)),
]
_RUN_WS_INSIDE = ["", " "]
_RUN_OUTER_WS = [("", ""), (" ", " ")]
_RUN_QUOTINGS = ["none", "double", "single"]


def _assign_run_text(spec: _AssignRunSpec, ws_inside: str) -> str:
    tokens = [
        char if rounds == 0 else _percent_encode_n(char, rounds)
        for char, rounds in spec
    ]
    return ws_inside.join(tokens)


_RunCase = tuple[_AssignRunSpec, str, tuple[str, str], str]


def _assign_run_cases() -> list[_RunCase]:
    cases: list[_RunCase] = []
    for spec in _ASSIGN_RUN_SPECS:
        for ws_inside in _RUN_WS_INSIDE:
            for outer_ws in _RUN_OUTER_WS:
                for quoting in _RUN_QUOTINGS:
                    cases.append((spec, ws_inside, outer_ws, quoting))
    return cases


_ASSIGN_RUN_CASES = _assign_run_cases()


@pytest.mark.parametrize(
    "case", _ASSIGN_RUN_CASES, ids=[f"run_{i}" for i in range(len(_ASSIGN_RUN_CASES))]
)
def test_assignment_run_grammar_redacts_secret(case: _RunCase) -> None:
    spec, ws_inside, outer_ws, quoting = case
    ws_pre, ws_post = outer_ws
    secret = "SECRET-run-" + "".join(
        str(hash((spec, ws_inside, outer_ws, quoting)))[-6:]
    )
    assign_run = _assign_run_text(spec, ws_inside)
    quoted_value = _quote_value(secret, quoting)
    text = f"PASSWORD{ws_pre}{assign_run}{ws_post}{quoted_value} {_TAIL}"
    result = redact_blob_for_display(text, frozenset(), frozenset())
    assert secret not in result, (
        f"secret leaked for run={spec} ws_inside={ws_inside!r} "
        f"outer_ws={outer_ws!r} quoting={quoting}: {result!r}"
    )


@pytest.mark.parametrize(
    "case",
    _ASSIGN_RUN_CASES,
    ids=[f"run_benign_{i}" for i in range(len(_ASSIGN_RUN_CASES))],
)
def test_assignment_run_grammar_preserves_benign_twin(case: _RunCase) -> None:
    spec, ws_inside, outer_ws, quoting = case
    ws_pre, ws_post = outer_ws
    assign_run = _assign_run_text(spec, ws_inside)
    quoted_value = _quote_value("benignvalue", quoting)
    text = f"{_BENIGN_NAME}{ws_pre}{assign_run}{ws_post}{quoted_value} {_TAIL}"
    assert redact_blob_for_display(text, frozenset(), frozenset()) == text


def _run_full_sweep() -> None:
    for case in _ALL_CASES:
        (
            name,
            ws_pre,
            ws_post,
            assign_char,
            separator,
            quoting,
            wrapper,
            rounds,
            target,
            name_quoting,
        ) = case
        _assert_secret_absent_case(
            name,
            ws_pre,
            ws_post,
            assign_char,
            separator,
            quoting,
            wrapper,
            rounds,
            target,
            name_quoting,
        )
        _assert_benign_twin_byte_identical(
            ws_pre, ws_post, assign_char, separator, quoting, wrapper, rounds, target
        )


def test_sensitive_pair_grammar_full_run_stays_within_time_budget() -> None:
    samples: list[float] = []
    for _ in range(5):
        start = time.process_time()
        _run_full_sweep()
        samples.append(time.process_time() - start)

    elapsed = min(samples)
    assert elapsed < _TIME_BUDGET_SECONDS, (
        f"generative sweep took {elapsed:.2f}s, over the {_TIME_BUDGET_SECONDS}s budget"
    )


_HIDDEN_WRAPPER_INNER_NAME = "password"
_HIDDEN_WRAPPER_BENIGN_INNER_NAME = _BENIGN_NAME
_HIDDEN_WRAPPER_OUTER_ENCODING_ROUNDS = [1, 2, 3]
_HIDDEN_WRAPPER_ASSIGN_RUN_SPECS: list[_AssignRunSpec] = [
    (("=", 0), ("=", 0)),
    ((":", 0), (":", 0)),
    (("=", 1), ("=", 0)),
    (("=", 0), ("=", 1)),
    (("=", 2), ("=", 3)),
]
_HIDDEN_WRAPPER_QUOTINGS = ["double", "single"]


def _hidden_wrapper_pair_text(
    outer_rounds: int,
    spec: _AssignRunSpec,
    quoting: str,
    separator: str,
    value: str,
    inner_name: str = _HIDDEN_WRAPPER_INNER_NAME,
) -> str:
    assign_run = _assign_run_text(spec, "")
    quoted_value = _quote_value(value, quoting)
    inner = f"{inner_name}{assign_run}{quoted_value}"
    wrapped = f'filename="{inner}"'
    outer_assign = _percent_encode_n("=", outer_rounds)
    return f"data{outer_assign}{wrapped}{separator}x=1{separator}y=2"


_HiddenWrapperCase = tuple[int, _AssignRunSpec, str, str]


def _hidden_wrapper_cases() -> list[_HiddenWrapperCase]:
    cases: list[_HiddenWrapperCase] = []
    for outer_rounds in _HIDDEN_WRAPPER_OUTER_ENCODING_ROUNDS:
        for spec in _HIDDEN_WRAPPER_ASSIGN_RUN_SPECS:
            for quoting in _HIDDEN_WRAPPER_QUOTINGS:
                for separator in _SEPARATORS:
                    cases.append((outer_rounds, spec, quoting, separator))
    return cases


_HIDDEN_WRAPPER_CASES = _hidden_wrapper_cases()


@pytest.mark.parametrize(
    "case",
    _HIDDEN_WRAPPER_CASES,
    ids=[f"hidden_wrapper_{i}" for i in range(len(_HIDDEN_WRAPPER_CASES))],
)
def test_hidden_assign_nested_quote_inside_encoded_outer_wrapper_redacts_secret(
    case: _HiddenWrapperCase,
) -> None:
    outer_rounds, spec, quoting, separator = case
    secret = "SECRET-hw-" + "".join(
        str(hash((outer_rounds, spec, quoting, separator)))[-6:]
    )
    text = _hidden_wrapper_pair_text(outer_rounds, spec, quoting, separator, secret)
    result = redact_blob_for_display(
        text, frozenset({_HIDDEN_WRAPPER_INNER_NAME}), frozenset()
    )
    assert secret not in result, (
        f"secret leaked for outer_rounds={outer_rounds} spec={spec} "
        f"quoting={quoting} separator={separator!r}: {result!r}"
    )


@pytest.mark.parametrize(
    "case",
    _HIDDEN_WRAPPER_CASES,
    ids=[f"hidden_wrapper_benign_{i}" for i in range(len(_HIDDEN_WRAPPER_CASES))],
)
def test_hidden_assign_nested_quote_inside_encoded_outer_wrapper_preserves_benign(
    case: _HiddenWrapperCase,
) -> None:
    outer_rounds, spec, quoting, separator = case
    text = _hidden_wrapper_pair_text(
        outer_rounds,
        spec,
        quoting,
        separator,
        "benignvalue",
        inner_name=_HIDDEN_WRAPPER_BENIGN_INNER_NAME,
    )
    result = redact_blob_for_display(text, frozenset(), frozenset())
    assert result == text


_JSON_LEAF_SPLIT_INNER_NAME = "password"
_JSON_LEAF_SPLIT_BENIGN_INNER_NAME = _BENIGN_NAME
_JSON_LEAF_SPLIT_ASSIGN_CHARS = ["=", ":"]
_ESCAPED_GAPS = [
    "\\t",
    "\\n",
    "\\r",
    "\\f",
    "\\x09",
    "\\X09",
    "\\u0020",
    "\\u{9}",
    "\\U00000009",
    "\\N{TAB}",
    "\\0",
    "\\011",
    '\\"',
    "\\'",
]
_JSON_LEAF_SPLIT_WS_COMBOS = [
    ("", ""),
    ("\t", ""),
    ("", "\t"),
    ("\t", "\t"),
    *[(gap, "") for gap in _ESCAPED_GAPS],
    *[(" " + gap + " ", "") for gap in _ESCAPED_GAPS],
]
_JSON_LEAF_SPLIT_QUOTINGS = ["double", "single"]
_JSON_LEAF_SPLIT_POSITIONS = ["path", "matrix"]


def _json_leaf_split_url(
    inner_name: str,
    ws_pre: str,
    ws_post: str,
    assign_char: str,
    quoting: str,
    value: str,
    position: str,
) -> str:
    quoted_value = _quote_value(value, quoting)
    pair = f"{inner_name}{ws_pre}{assign_char}{ws_post}{quoted_value}"
    note_text = f"x=1?y=2?{pair}?z=3"
    blob = json.dumps({"note": note_text})
    if position == "matrix":
        return f"https://test/resource;{blob}"
    return f"https://test/{blob}"


_JsonLeafSplitCase = tuple[str, str, str, str, str]


def _json_leaf_split_cases() -> list[_JsonLeafSplitCase]:
    cases: list[_JsonLeafSplitCase] = []
    for ws_pre, ws_post in _JSON_LEAF_SPLIT_WS_COMBOS:
        for assign_char in _JSON_LEAF_SPLIT_ASSIGN_CHARS:
            for quoting in _JSON_LEAF_SPLIT_QUOTINGS:
                for position in _JSON_LEAF_SPLIT_POSITIONS:
                    cases.append((ws_pre, ws_post, assign_char, quoting, position))
    return cases


_JSON_LEAF_SPLIT_CASES = _json_leaf_split_cases()


@pytest.mark.parametrize(
    "case",
    _JSON_LEAF_SPLIT_CASES,
    ids=[f"json_leaf_split_{i}" for i in range(len(_JSON_LEAF_SPLIT_CASES))],
)
def test_json_leaf_value_containing_query_char_and_hidden_assign_redacts_secret(
    case: _JsonLeafSplitCase,
) -> None:
    ws_pre, ws_post, assign_char, quoting, position = case
    secret = "SECRET-jls-" + "".join(
        str(hash((ws_pre, ws_post, assign_char, quoting, position)))[-6:]
    )
    url = _json_leaf_split_url(
        _JSON_LEAF_SPLIT_INNER_NAME,
        ws_pre,
        ws_post,
        assign_char,
        quoting,
        secret,
        position,
    )
    result = redact_url_for_display(url, frozenset(), frozenset())
    assert secret not in result, (
        f"secret leaked for ws=({ws_pre!r},{ws_post!r}) assign={assign_char!r} "
        f"quoting={quoting} position={position}: {result!r}"
    )


@pytest.mark.parametrize(
    "case",
    _JSON_LEAF_SPLIT_CASES,
    ids=[f"json_leaf_split_benign_{i}" for i in range(len(_JSON_LEAF_SPLIT_CASES))],
)
def test_json_leaf_value_containing_query_char_and_hidden_assign_preserves_benign(
    case: _JsonLeafSplitCase,
) -> None:
    ws_pre, ws_post, assign_char, quoting, position = case
    url = _json_leaf_split_url(
        _JSON_LEAF_SPLIT_BENIGN_INNER_NAME,
        ws_pre,
        ws_post,
        assign_char,
        quoting,
        "benignvalue",
        position,
    )
    result = redact_url_for_display(url, frozenset(), frozenset())
    assert result == url


_ESCAPED_GAP_CASES = [
    (gap, assign_char, surface)
    for gap in _ESCAPED_GAPS
    for assign_char in _JSON_LEAF_SPLIT_ASSIGN_CHARS
    for surface in ("header", "matrix", "json_leaf")
]


def _escaped_gap_text(
    name: str, gap: str, assign_char: str, value: str, surface: str
) -> str:
    pair = f"{name}{gap}{assign_char}{value}"
    if surface == "header":
        return f"Mozilla/5.0 {pair} x=1"
    if surface == "matrix":
        return f"https://test/orders;{pair}/x"
    return f"https://test/resource;{json.dumps({'note': pair})}"


def _redact_escaped_gap_text(text: str, surface: str) -> str:
    if surface == "header":
        return redact_blob_for_display(text, frozenset(), frozenset(), frozenset())
    return redact_url_for_display(text, frozenset(), frozenset())


@pytest.mark.parametrize(
    "case",
    _ESCAPED_GAP_CASES,
    ids=[f"escaped_gap_{i}" for i in range(len(_ESCAPED_GAP_CASES))],
)
def test_escaped_whitespace_or_quote_before_assignment_redacts_secret(
    case: tuple[str, str, str],
) -> None:
    gap, assign_char, surface = case
    secret = "SECRET-egap-" + str(abs(hash(case)))[-6:]
    text = _escaped_gap_text("password", gap, assign_char, secret, surface)
    result = _redact_escaped_gap_text(text, surface)
    assert secret not in result, (
        f"gap={gap!r} assign={assign_char!r} {surface}: {result!r}"
    )


@pytest.mark.parametrize(
    "case",
    _ESCAPED_GAP_CASES,
    ids=[f"escaped_gap_benign_{i}" for i in range(len(_ESCAPED_GAP_CASES))],
)
def test_escaped_whitespace_or_quote_before_assignment_preserves_benign(
    case: tuple[str, str, str],
) -> None:
    gap, assign_char, surface = case
    text = _escaped_gap_text(_BENIGN_NAME, gap, assign_char, "benignvalue", surface)
    assert _redact_escaped_gap_text(text, surface) == text


def test_escaped_gap_length_ignores_escapes_that_decode_to_content() -> None:
    from guard_core.sync._utils.pair_hidden_assign import _escaped_gap_length

    assert _escaped_gap_length("\\x41=1", 0) == 0
    assert _escaped_gap_length("\\u0041=1", 0) == 0
    assert _escaped_gap_length("\\z=1", 0) == 0
    assert _escaped_gap_length("\\x09=1", 0) == 4
    assert _escaped_gap_length("\\u0009=1", 0) == 6
    assert _escaped_gap_length("\\n=1", 0) == 2
    assert _escaped_gap_length("\\101=1", 0) == 0
    assert _escaped_gap_length("\\011=1", 0) == 4
    assert _escaped_gap_length("\\N{LATIN SMALL LETTER A}=1", 0) == 0
    assert _escaped_gap_length("\\N{NO SUCH NAME}=1", 0) == 0
    assert _escaped_gap_length("\\N{TAB}=1", 0) == 7
    assert _escaped_gap_length("\\U0001F600=1", 0) == 0
    assert _escaped_gap_length("\\U00110000=1", 0) == 0
    assert _escaped_gap_length("\\u{20}=1", 0) == 6


_NESTED_QUOTE_PATH_SECRET = "SECRET-nested-quote-path"
_NESTED_QUOTE_PATH_URL = (
    'https://test/filename="x=1%2520password%2520:%2520"'
    + _NESTED_QUOTE_PATH_SECRET
    + '%2520<script>alert(1)</script>"%2520y=2"'
)


def test_quoted_value_cut_by_a_slash_in_the_nested_value_redacts_to_segment_end() -> (
    None
):
    result = redact_url_for_display(_NESTED_QUOTE_PATH_URL, frozenset(), frozenset())
    assert _NESTED_QUOTE_PATH_SECRET not in result


def test_quoted_value_cut_by_a_slash_preserves_a_benign_twin() -> None:
    url = _NESTED_QUOTE_PATH_URL.replace("password", "note")
    assert redact_url_for_display(url, frozenset(), frozenset()) == url


def test_restart_value_extent_consumes_to_the_end_when_the_quote_never_closes() -> None:
    from guard_core.sync._utils.pair_value_scan import _restart_value_extent_at_quote

    assert _restart_value_extent_at_quote('x"rest of text', 1, "", True) == ('"', 14)
    assert _restart_value_extent_at_quote('x"rest of text', 1, "", False) == ("", 1)
    assert _restart_value_extent_at_quote('x"a"b', 1, "", False) == ('"', 3)
