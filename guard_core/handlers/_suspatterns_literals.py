import importlib
import re
import sys
from collections.abc import Iterator
from typing import Any

_PARSER = importlib.import_module(
    "re._parser" if sys.version_info >= (3, 11) else "sre_parse"
)

_MIN_LITERAL_LENGTH = 3
_FOLD = {0x130: "i", 0x131: "i", 0x17F: "s", 0x212A: "k"}
_required_literals: dict[str, tuple[str, ...]] = {}


def fold_for_literals(text: str) -> str:
    return text.translate(_FOLD).lower()


def _usable(run: str) -> bool:
    return len(run) >= _MIN_LITERAL_LENGTH and run.isascii() and run.isprintable()


def _requirements(items: Any) -> list[tuple[str, ...]]:
    found: list[tuple[str, ...]] = []
    current: list[int] = []

    def close_run() -> None:
        run = "".join(map(chr, current))
        current.clear()
        if _usable(run):
            found.append((run.lower(),))

    for op, argument in items:
        name = str(op)
        if name == "LITERAL":
            current.append(argument)
            continue
        close_run()
        if name == "SUBPATTERN":
            found.extend(_requirements(argument[3]))
        elif name in ("MAX_REPEAT", "MIN_REPEAT") and argument[0] >= 1:
            found.extend(_requirements(argument[2]))
        elif name == "BRANCH":
            found.extend(_branch_requirement(argument[1]))
    close_run()
    return found


def _branch_requirement(branches: Any) -> list[tuple[str, ...]]:
    alternatives: list[str] = []
    for branch in branches:
        best = _best_requirement(_requirements(branch))
        if best is None:
            return []
        alternatives.extend(best)
    return [tuple(dict.fromkeys(alternatives))]


def _best_requirement(
    candidates: list[tuple[str, ...]],
) -> tuple[str, ...] | None:
    if not candidates:
        return None
    return max(candidates, key=lambda alts: (min(map(len, alts)), -len(alts)))


def required_literals(source: str) -> tuple[str, ...]:
    if source not in _required_literals:
        try:
            parsed = _PARSER.parse(source, re.IGNORECASE)
            best = _best_requirement(_requirements(parsed))
        except Exception:
            best = None
        _required_literals[source] = best or ()
    return _required_literals[source]


def rows_with_required_literal(
    rows: list[tuple[re.Pattern, frozenset[str], str]],
    folded_content: str,
    excluded_sources: frozenset[str],
) -> Iterator[tuple[re.Pattern, frozenset[str], str]]:
    present: dict[str, bool] = {}
    for row in rows:
        source = row[0].pattern
        literals = () if source in excluded_sources else required_literals(source)
        if not literals:
            yield row
            continue
        for literal in literals:
            found = present.get(literal)
            if found is None:
                found = present[literal] = literal in folded_content
            if found:
                yield row
                break
