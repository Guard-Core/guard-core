from collections.abc import MutableMapping
from typing import Any, cast

from guard_core.sync.core.responses.factory import _merge_security_headers


class TupleIterHeaders(MutableMapping[str, str]):
    """A case-insensitive container that iterates (name, value) pairs like Werkzeug."""

    def __init__(self, pairs: list[tuple[str, str]]) -> None:
        self._pairs = list(pairs)

    def __iter__(self) -> Any:
        return iter(self._pairs)

    def keys(self) -> Any:
        return [name for name, _ in self._pairs]

    def __len__(self) -> int:
        return len(self._pairs)

    def __getitem__(self, name: str) -> str:
        for key, value in self._pairs:
            if key.lower() == name.lower():
                return value
        raise KeyError(name)

    def __setitem__(self, name: str, value: str) -> None:
        self._pairs = [(k, v) for k, v in self._pairs if k.lower() != name.lower()]
        self._pairs.append((name, value))

    def __delitem__(self, name: str) -> None:
        self._pairs = [(k, v) for k, v in self._pairs if k.lower() != name.lower()]


def test_tuple_iterating_container_keeps_existing_and_forces_listed() -> None:
    headers = TupleIterHeaders(
        [("content-type", "text/html"), ("x-frame-options", "ALLOW")]
    )
    security = {
        "X-Content-Type-Options": "nosniff",
        "Content-Type": "ignored",
        "X-Frame-Options": "DENY",
    }
    _merge_security_headers(headers, security, frozenset({"x-frame-options"}))
    assert headers["content-type"] == "text/html"
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"


class ContainsOnlyHeaders:
    """A Django response used as its own header mapping: no keys(), no pairs."""

    def __init__(self, values: dict[str, str]) -> None:
        self._values = {key.lower(): (key, value) for key, value in values.items()}

    def __iter__(self) -> Any:
        return iter([b"body"])

    def __contains__(self, name: str) -> bool:
        return name.lower() in self._values

    def __getitem__(self, name: str) -> str:
        return self._values[name.lower()][1]

    def __setitem__(self, name: str, value: str) -> None:
        self._values[name.lower()] = (name, value)


def test_container_with_only_item_access_and_membership() -> None:
    headers = ContainsOnlyHeaders(
        {"content-type": "text/html", "x-frame-options": "ALLOW"}
    )
    security = {
        "X-Content-Type-Options": "nosniff",
        "Content-Type": "ignored",
        "X-Frame-Options": "DENY",
    }
    _merge_security_headers(
        cast(MutableMapping[str, str], headers),
        security,
        frozenset({"x-frame-options"}),
    )
    assert headers["content-type"] == "text/html"
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"
