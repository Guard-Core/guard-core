import pytest

from guard_core.handlers import _suspatterns_linear_path
from guard_core.handlers._suspatterns_linear_path import (
    _BUCKET_MIN_CHARS,
    tail_source_and_parts,
)
from guard_core.handlers._suspatterns_linear_path_source import (
    _sliced,
    flattened,
    row_pieces,
    row_spans,
    unbalanced_parenthesis_spans,
    without_spans,
    without_unbalanced_parentheses,
)
from guard_core.handlers._suspatterns_linear_split_table import (
    BUILTIN_ROW_SPANS,
    BUILTIN_TAIL_SPLITS,
)
from guard_core.handlers._suspatterns_literals import source_digest
from guard_core.handlers._suspatterns_pattern_table import _PATTERN_DEFINITIONS
from guard_core.handlers._suspatterns_tail_buckets import (
    AlternationParts,
    alternation_from_layout,
    alternation_layout,
    split_alternation,
)

_BUILTIN_SOURCES = [source for source, _contexts, _category in _PATTERN_DEFINITIONS]


def _tail_pieces_of_every_builtin_linear_row() -> list[str]:
    pieces: list[str] = []
    for source in _BUILTIN_SOURCES:
        spans = row_spans(source)
        if spans is not None:
            row = _sliced(source, *spans)[0]
            pieces.extend(map(flattened, row[1:]))
    return pieces


def _long_alternation(branches: int) -> str:
    return "(?=[a-z])(?:" + "|".join(f"a{i:04d}x" for i in range(branches)) + ")\\.php"


def test_the_row_table_is_the_split_of_every_builtin_row() -> None:
    expected = {}
    for source in _BUILTIN_SOURCES:
        spans = row_spans(source)
        expected[source_digest(source)] = (
            None if spans is None else (tuple(spans[0]), tuple(spans[1]))
        )

    assert BUILTIN_ROW_SPANS == expected


def test_a_builtin_row_is_split_without_parsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    computed = {source: row_pieces(source) for source in _BUILTIN_SOURCES}
    monkeypatch.setattr(
        "guard_core.handlers._suspatterns_linear_path_source.row_spans",
        lambda _source: pytest.fail("parsed a builtin row"),
    )

    for source in _BUILTIN_SOURCES:
        assert row_pieces(source) == computed[source]


def test_a_custom_row_is_split_by_parsing() -> None:
    linear = r"\A[/\\]?(?:[\w.\-~%]+[/\\])*(?:foo|bar)\.php\Z"
    plain = r"union\s+select"

    split = row_pieces(linear)

    assert split is not None
    assert "".join(split[0]).startswith(r"\A[/\\]?")
    assert row_pieces(plain) is None


def test_the_tail_table_is_the_split_of_every_long_builtin_tail() -> None:
    expected = {}
    for piece in _tail_pieces_of_every_builtin_linear_row():
        removed = unbalanced_parenthesis_spans(piece)
        tail = without_spans(piece, removed)
        parts = split_alternation(tail) if len(tail) > _BUCKET_MIN_CHARS else None
        if parts is not None:
            expected[source_digest(piece)] = (
                tuple(removed),
                alternation_layout(tail, parts),
            )

    assert expected
    assert BUILTIN_TAIL_SPLITS == expected


def test_a_builtin_tail_is_split_without_scanning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pieces = _tail_pieces_of_every_builtin_linear_row()
    computed = {piece: tail_source_and_parts(piece) for piece in pieces}
    monkeypatch.setattr(
        _suspatterns_linear_path,
        "split_alternation",
        lambda _source: pytest.fail("scanned a builtin tail"),
    )
    monkeypatch.setattr(
        _suspatterns_linear_path,
        "without_unbalanced_parentheses",
        lambda _piece: pytest.fail("scanned a builtin tail"),
    )

    for piece in pieces:
        if source_digest(piece) in BUILTIN_TAIL_SPLITS:
            source, parts = tail_source_and_parts(piece)
            assert (source, parts) == computed[piece]
            assert parts is not None


def test_a_custom_long_tail_is_split_by_scanning() -> None:
    piece = _long_alternation(600)

    source, parts = tail_source_and_parts(piece)

    assert source == without_unbalanced_parentheses(piece)
    assert len(source) > _BUCKET_MIN_CHARS
    assert parts == split_alternation(source)
    assert parts is not None
    assert len(parts.branches) == 600


def test_a_short_tail_is_not_split() -> None:
    source, parts = tail_source_and_parts(r"(?:foo|bar)\.php")

    assert source == r"(?:foo|bar)\.php"
    assert parts is None


def test_an_alternation_layout_rebuilds_the_parts_it_came_from() -> None:
    wrapped = r"(?=[a-z])(?:(?:(?:a0000x|a0001x|a0002x)))\.php"
    for source in (_long_alternation(3), wrapped):
        parts = split_alternation(source)
        assert parts is not None

        layout = alternation_layout(source, parts)

        assert alternation_from_layout(source, layout) == parts


def test_an_alternation_layout_refuses_branches_that_are_not_in_the_source() -> None:
    parts = AlternationParts("", ("zz",), "")

    with pytest.raises(ValueError, match="do not lie inside the source"):
        alternation_layout("abc", parts)
