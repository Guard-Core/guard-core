import pytest

from guard_core.handlers import _suspatterns_literals
from guard_core.handlers._suspatterns_literal_table import BUILTIN_REQUIRED_LITERALS
from guard_core.handlers._suspatterns_literals import (
    parse_required_literals,
    required_literals,
    source_digest,
)
from guard_core.handlers._suspatterns_pattern_table import _PATTERN_DEFINITIONS


def test_the_literal_table_is_the_extraction_of_every_builtin_row() -> None:
    expected = {
        source_digest(source): parse_required_literals(source)
        for source, _contexts, _category in _PATTERN_DEFINITIONS
    }
    assert BUILTIN_REQUIRED_LITERALS == expected


def test_a_builtin_row_needs_no_parse_for_its_required_literals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_suspatterns_literals, "_required_literals", {})
    monkeypatch.setattr(
        _suspatterns_literals,
        "parse_required_literals",
        lambda _source: pytest.fail("parsed a builtin row"),
    )
    for source, _contexts, _category in _PATTERN_DEFINITIONS:
        assert (
            required_literals(source)
            == BUILTIN_REQUIRED_LITERALS[source_digest(source)]
        )
