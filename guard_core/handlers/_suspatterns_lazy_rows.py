import re
from typing import Any, NamedTuple

_BUILTIN_PATTERN_COMPILE_FLAGS = re.IGNORECASE


class _SourceRow(NamedTuple):
    pattern: str
    position: int


class _SusPatternsLazyRowsMixin:
    compiled_custom_patterns: set[tuple[re.Pattern, frozenset[str], str]]
    _pattern_definitions: list[tuple[str, frozenset[str], str]]
    _compiled_rows: list[tuple[re.Pattern, frozenset[str], str]] | None
    _compiled_builtin_rows: dict[int, tuple[re.Pattern, frozenset[str], str]]
    _source_rows_cache: list[tuple[_SourceRow, frozenset[str], str]] | None

    @property
    def compiled_patterns(self) -> list[tuple[re.Pattern, frozenset[str], str]]:
        if self._compiled_rows is None:
            self._compiled_rows = [
                self._compiled_builtin_row(index)
                for index in range(len(self._pattern_definitions))
            ]
        return self._compiled_rows

    @compiled_patterns.setter
    def compiled_patterns(
        self, rows: list[tuple[re.Pattern, frozenset[str], str]]
    ) -> None:
        self._compiled_rows = rows

    def _compiled_builtin_row(
        self, index: int
    ) -> tuple[re.Pattern, frozenset[str], str]:
        row = self._compiled_builtin_rows.get(index)
        if row is None:
            source, contexts, category = self._pattern_definitions[index]
            row = (
                re.compile(source, _BUILTIN_PATTERN_COMPILE_FLAGS),
                contexts,
                category,
            )
            self._compiled_builtin_rows[index] = row
        return row

    def _rows_without_compiling(self) -> list[tuple[Any, frozenset[str], str]]:
        if self._source_rows_cache is None:
            self._source_rows_cache = [
                (_SourceRow(source, index), contexts, category)
                for index, (source, contexts, category) in enumerate(
                    self._pattern_definitions
                )
            ]
        return [*self._source_rows_cache, *self.compiled_custom_patterns]

    def _compiled_row(
        self, row: tuple[Any, frozenset[str], str]
    ) -> tuple[re.Pattern, frozenset[str], str]:
        source = row[0]
        if isinstance(source, _SourceRow):
            return self._compiled_builtin_row(source.position)
        return row
