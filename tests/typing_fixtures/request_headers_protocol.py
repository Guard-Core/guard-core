from collections.abc import Iterator
from typing import overload

from guard_core.protocols import GuardRequestHeaders


class PairIterationHeaders:
    """The shape of Werkzeug ``EnvironHeaders``: iterating yields pairs."""

    def __init__(self, pairs: list[tuple[str, str]]) -> None:
        self._pairs = pairs

    def __iter__(self) -> Iterator[tuple[str, str]]:
        return iter(self._pairs)

    def __contains__(self, key: str) -> bool:
        return any(name.lower() == key.lower() for name, _ in self._pairs)

    def __getitem__(self, key: str) -> str:
        for name, value in self._pairs:
            if name.lower() == key.lower():
                return value
        raise KeyError(key)

    @overload
    def get(self, key: str, /) -> str | None: ...

    @overload
    def get(self, key: str, default: str, /) -> str: ...

    def get(self, key: str, default: str | None = None, /) -> str | None:
        try:
            return self[key]
        except KeyError:
            return default

    def keys(self) -> Iterator[str]:
        return (name for name, _ in self._pairs)

    def items(self) -> Iterator[tuple[str, str]]:
        return iter(self._pairs)


plain: GuardRequestHeaders = {"host": "example.com"}
pair_iterating: GuardRequestHeaders = PairIterationHeaders([("host", "example.com")])
copied: dict[str, str] = dict(pair_iterating)
with_default: str = plain.get("host", "")
without_default: str | None = plain.get("host")
