import re
from collections.abc import Callable, Iterator, Mapping


class LazyPatterns(dict[str, "re.Pattern[str]"]):
    """Patterns that compile on the first lookup of their name.

    WHY: a module that compiles a rare-path pattern at import makes every
    process pay for it, so the process that never reaches that path pays too.
    HOW: a hit is a plain dict read, so a hot path pays no extra call.
    """

    def __init__(self, definitions: Mapping[str, tuple[str, int]]) -> None:
        super().__init__()
        self._definitions = definitions

    def __missing__(self, name: str) -> "re.Pattern[str]":
        source, flags = self._definitions[name]
        compiled = self[name] = re.compile(source, flags)
        return compiled


class CompiledOnDemand(dict[str, "re.Pattern[str]"]):
    """Any source, compiled on its first lookup with one fixed set of flags."""

    def __init__(self, flags: int) -> None:
        super().__init__()
        self._flags = flags

    def __missing__(self, source: str) -> "re.Pattern[str]":
        compiled = self[source] = re.compile(source, self._flags)
        return compiled


class LazyPatternMap(Mapping[str, "re.Pattern[str]"]):
    """A mapping from a key to the pattern of its source, compiled on first read."""

    def __init__(self, sources: Mapping[str, str], compiled: CompiledOnDemand) -> None:
        self._sources = sources
        self._compiled = compiled

    def __getitem__(self, key: str) -> "re.Pattern[str]":
        return self._compiled[self._sources[key]]

    def __iter__(self) -> Iterator[str]:
        return iter(self._sources)

    def __len__(self) -> int:
        return len(self._sources)


def module_attribute_lookup(
    *tables: LazyPatterns,
) -> Callable[[str], "re.Pattern[str]"]:
    """The lookup behind a module ``__getattr__``, so ``from module import NAME``
    keeps working for a pattern that compiles on first use."""

    def lookup(name: str) -> "re.Pattern[str]":
        for table in tables:
            if name in table._definitions:
                return table[name]
        raise AttributeError(name)

    return lookup
