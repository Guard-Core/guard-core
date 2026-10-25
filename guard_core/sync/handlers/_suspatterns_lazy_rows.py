import re
from functools import cached_property
from typing import TYPE_CHECKING, Any, NamedTuple

from guard_core.sync._utils.scan_config_scope import scoped_config
from guard_core.sync.handlers._suspatterns_pattern_table import BARE_UNION_SELECT_ROW

if TYPE_CHECKING:
    from guard_core.models import SyncSecurityConfig

_BUILTIN_PATTERN_COMPILE_FLAGS = re.IGNORECASE


class _CompiledBuiltinPatterns(dict[str, re.Pattern]):
    def __missing__(self, source: str) -> re.Pattern:
        compiled = re.compile(source, _BUILTIN_PATTERN_COMPILE_FLAGS)
        self[source] = compiled
        return compiled


COMPILED_BUILTIN_PATTERNS = _CompiledBuiltinPatterns()


def disabled_row_sources_of(config: "SyncSecurityConfig") -> frozenset[str]:
    return (
        frozenset()
        if getattr(config, "flag_bare_union_select", True)
        else frozenset({BARE_UNION_SELECT_ROW})
    )


class _SourceRow(NamedTuple):
    pattern: str


class _SusPatternsLazyRowsMixin:
    _pattern_definitions: list[tuple[str, frozenset[str], str]]
    compiled_custom_patterns: set[tuple[re.Pattern, frozenset[str], str]]
    _config: "SyncSecurityConfig | None" = None
    _disabled_row_sources: frozenset[str] = frozenset()

    def _scan_config(self) -> "SyncSecurityConfig | None":
        return scoped_config(self, self._config)

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

    def _rows_to_scan(self) -> list[tuple[Any, frozenset[str], str]]:
        builtin_rows = (
            self.compiled_patterns
            if "compiled_patterns" in self.__dict__
            else self._source_rows
        )
        return [
            *self._without_disabled_rows(builtin_rows),
            *self.compiled_custom_patterns,
        ]

    def _without_disabled_rows(self, rows: list[Any]) -> list[Any]:
        request_config = scoped_config(self, None)
        disabled = (
            self._disabled_row_sources
            if request_config is None
            else disabled_row_sources_of(request_config)
        )
        return (
            [row for row in rows if row[0].pattern not in disabled]
            if disabled
            else rows
        )
