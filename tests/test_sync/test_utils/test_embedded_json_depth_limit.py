import json
from collections.abc import Callable
from typing import Any

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils import embedded_json_scan
from guard_core.sync._utils.detection_scan import _scan_value_budget
from guard_core.sync._utils.embedded_json_scan import (
    _EMBEDDED_JSON_MAX_PARSE_DEPTH,
    _check_embedded_json,
    _decoded_string_literal,
    _escaped_string_literals,
    _nests_deeper_than,
)
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

LIMIT = _EMBEDDED_JSON_MAX_PARSE_DEPTH
XSS_ESCAPED = "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


def _walk(value: str) -> tuple[bool, str, list[dict], str | None] | None:
    return _check_embedded_json(
        value,
        "query_param:v",
        "127.0.0.1",
        "corr-1",
        None,
        frozenset(),
        frozenset(),
        False,
    )


def test_the_limit_is_below_the_lowest_parser_limit_measured() -> None:
    assert LIMIT < 951


@pytest.mark.parametrize(
    ("value", "deeper"),
    [
        ("[" * LIMIT + "]" * LIMIT, False),
        ("[" * (LIMIT + 1) + "]" * (LIMIT + 1), True),
        ('{"a":' * (LIMIT + 1) + "1" + "}" * (LIMIT + 1), True),
        (json.dumps("[" * (LIMIT + 5)), False),
        ('"\\"' + "[" * (LIMIT + 5) + '"', False),
        ("[" * LIMIT + json.dumps("[" * 50) + "]" * LIMIT, False),
        ("[" * (LIMIT - 1) + json.dumps("]" * 50) + "[" + "]" * LIMIT, False),
        ("[" * (LIMIT + 1) + '"' + "]" * 50 + '"' + "]" * (LIMIT + 1), True),
        ("[]" * (LIMIT * 3), False),
    ],
    ids=[
        "at the limit",
        "one past",
        "objects past",
        "brackets inside a string",
        "escaped quote keeps the string open",
        "string of openers under the limit",
        "closers in a string do not lower the depth",
        "string between deep openers",
        "many siblings are not deep",
    ],
)
def test_the_bracket_count_is_string_aware_and_stops_at_the_limit(
    value: str, deeper: bool
) -> None:
    assert _nests_deeper_than(value, LIMIT) is deeper


def test_a_value_with_few_openers_skips_the_count() -> None:
    assert _nests_deeper_than("[" * 3, 5) is False


def test_only_the_escaped_literals_are_returned_and_none_is_read_recursively() -> None:
    text = '{"a": ["b\\"c", "d\\\\"], "e": "f"}'
    assert _escaped_string_literals(text) == ['b\\"c', "d\\\\"]


def test_a_value_with_no_backslash_has_no_escaped_literal() -> None:
    assert _escaped_string_literals('["a", "b"]') == []


def test_an_unterminated_literal_is_dropped() -> None:
    assert _escaped_string_literals('["a\\n", "b\\n') == ["a\\n"]


def test_a_literal_is_decoded_and_an_undecodable_one_is_kept() -> None:
    assert _decoded_string_literal("\\u003c") == "<"
    assert _decoded_string_literal("a\nb") == "a\nb"
    assert _decoded_string_literal("bad\\qescape") == "bad\\qescape"


def test_a_long_run_of_backslashes_is_read_in_linear_time() -> None:
    text = '"' + "\\" * 200_000 + "x"
    assert _escaped_string_literals(text) == []
    assert _nests_deeper_than("[" * 600 + text, LIMIT) is True


@pytest.mark.parametrize("depth", [LIMIT + 1, 3000])
def test_a_value_past_the_limit_is_decoded_literal_by_literal(
    depth: int,
) -> None:
    inner = '{"q":"' + XSS_ESCAPED + '"}'
    value = "[" * depth + json.dumps(inner) + "]" * depth
    result = _walk(value)
    assert result is not None
    assert result[0] is True
    assert result[3] == "[REDACTED]"


def test_a_benign_value_past_the_limit_is_clean() -> None:
    value = "[" * 3000 + json.dumps("hello") + "]" * 3000
    assert _walk(value) is None


def test_a_literal_that_is_json_goes_back_through_the_walk() -> None:
    payload: Any = {"q": XSS_ESCAPED}
    once = json.dumps(payload)
    twice = json.dumps({"k": once})
    value = "[" * 3000 + json.dumps(twice) + "]" * 3000
    result = _walk(value)
    assert result is not None
    assert result[0] is True


def test_the_literal_scan_stops_when_the_value_budget_is_spent() -> None:
    literals = ",".join(['"x\\n"'] * 10 + ['"<script>alert(1)</script>\\n"'])
    value = "[" * 600 + literals + "]" * 600
    with _scan_value_budget(3):
        assert _walk(value) is None


def test_a_value_that_is_not_a_container_is_not_walked() -> None:
    assert _walk("123") is None


def test_a_parser_that_raises_its_recursion_error_is_treated_as_too_deep(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_loads = json.loads

    def refuse(
        text: str,
        *,
        strict: bool = True,
        object_pairs_hook: Callable[[list[tuple[str, object]]], object] | None = None,
    ) -> object:
        if text.startswith('"'):
            return real_loads(text, strict=strict, object_pairs_hook=object_pairs_hook)
        raise RecursionError

    monkeypatch.setattr(embedded_json_scan.json, "loads", refuse)
    value = json.dumps({"q": XSS_ESCAPED})
    result = _walk(value)
    assert result is not None
    assert result[0] is True
