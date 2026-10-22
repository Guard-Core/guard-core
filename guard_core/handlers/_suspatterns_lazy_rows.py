import re
from functools import cached_property
from typing import Any, NamedTuple

_BUILTIN_PATTERN_COMPILE_FLAGS = re.IGNORECASE


class _CompiledBuiltinPatterns(dict[str, re.Pattern]):
    def __missing__(self, source: str) -> re.Pattern:
        compiled = re.compile(source, _BUILTIN_PATTERN_COMPILE_FLAGS)
        self[source] = compiled
        return compiled


COMPILED_BUILTIN_PATTERNS = _CompiledBuiltinPatterns()


class _SourceRow(NamedTuple):
    pattern: str


class _SusPatternsLazyRowsMixin:
    _pattern_definitions: list[tuple[str, frozenset[str], str]]
    compiled_custom_patterns: set[tuple[re.Pattern, frozenset[str], str]]

    @cached_property
    def compiled_patterns(self) -> list[tuple[re.Pattern, frozenset[str], str]]:
        return [
            (COMPILED_BUILTIN_PATTERNS[source], contexts, category)
            for source, contexts, category in self._pattern_definitions
        ]

    @cached_property
    def _source_rows(self) -> list[tuple[_SourceRow, frozenset[str], str]]:
        return [
            (_SourceRow(source), contexts, category)
            for source, contexts, category in self._pattern_definitions
        ]

    async def _rows_to_scan(self) -> list[tuple[Any, frozenset[str], str]]:
        builtin_rows = (
            self.compiled_patterns
            if "compiled_patterns" in self.__dict__
            else self._source_rows
        )
        return [*builtin_rows, *self.compiled_custom_patterns]
