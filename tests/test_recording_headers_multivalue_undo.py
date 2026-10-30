from collections.abc import Iterator

import pytest

from guard_core.core.responses.modifier_view import RecordingHeaders


class _MultiValueHeaders:
    """Starlette's MutableHeaders behavior: one name may hold several values,
    ``[]`` reads the first, assigns and deletes replace or drop them all."""

    def __init__(self, items: list[tuple[str, str]]) -> None:
        self._items = list(items)

    def __getitem__(self, key: str) -> str:
        for name, value in self._items:
            if name == key.lower():
                return value
        raise KeyError(key)

    def __setitem__(self, key: str, value: str) -> None:
        self._items = [(n, v) for n, v in self._items if n != key.lower()]
        self._items.append((key.lower(), value))

    def __delitem__(self, key: str) -> None:
        if not any(name == key.lower() for name, _ in self._items):
            raise KeyError(key)
        self._items = [(n, v) for n, v in self._items if n != key.lower()]

    def __contains__(self, key: str) -> bool:
        return any(name == key.lower() for name, _ in self._items)

    def append(self, key: str, value: str) -> None:
        self._items.append((key.lower(), value))

    def items(self) -> list[tuple[str, str]]:
        return list(self._items)

    def get(self, key: str, default: str | None = None) -> str | None:
        return self[key] if key in self else default

    def keys(self) -> list[str]:
        return [name for name, _ in self._items]

    def __iter__(self) -> Iterator[str]:
        return iter(self.keys())

    def __len__(self) -> int:
        return len(self._items)

    def getlist(self, key: str) -> list[str]:
        return [v for n, v in self._items if n == key.lower()]


def _fresh() -> _MultiValueHeaders:
    return _MultiValueHeaders(
        [("set-cookie", "a=1"), ("set-cookie", "b=2"), ("x-keep", "1")]
    )


@pytest.mark.parametrize("operation", ["overwrite", "delete"])
def test_undo_restores_every_value_of_a_multi_valued_header(operation: str) -> None:
    real = _fresh()
    recording = RecordingHeaders(real)
    if operation == "overwrite":
        recording["set-cookie"] = "c=3"
    else:
        del recording["set-cookie"]

    recording.undo()

    assert real.getlist("set-cookie") == ["a=1", "b=2"]
    assert real.getlist("x-keep") == ["1"]
