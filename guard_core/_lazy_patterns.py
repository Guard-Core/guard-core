import functools
import re
from collections.abc import Callable, Iterable, Iterator, Mapping
from typing import Protocol


class _Table(Protocol):
    @property
    def _definitions(self) -> Iterable[str]: ...

    def __getitem__(self, name: str) -> "re.Pattern[str]": ...


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


class _LazyName:
    """The class-level attribute of one lazily compiled name: it compiles on its
    first read and keeps the result on the instance, so later reads are plain
    dict hits."""

    __slots__ = ("_name", "_table")

    def __init__(self, table: _Table, name: str) -> None:
        self._table = table
        self._name = name

    def __get__(self, instance: object, owner: type | None = None) -> "re.Pattern[str]":
        compiled = self._table[self._name]
        if instance is not None:
            instance.__dict__[self._name] = compiled
        return compiled


def module_attribute_lookup(*tables: _Table) -> Callable[[str], "re.Pattern[str]"]:
    """The ``__getattr__`` of a module whose patterns compile on first use, so
    ``from module import NAME`` keeps working.

    It is built from ``getattr`` on a namespace object, so it runs in C: a name it
    does not know (the ``__path__`` probe of every ``from module import x`` that
    runs inside a function) raises AttributeError without a Python frame.
    """
    names: dict[str, _LazyName] = {}
    for table in tables:
        for name in table._definitions:
            names.setdefault(name, _LazyName(table, name))
    return functools.partial(getattr, type("LazyPatternNames", (), names)())
