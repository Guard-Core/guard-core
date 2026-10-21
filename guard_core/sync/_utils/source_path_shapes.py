import contextvars
from typing import Any, NamedTuple


class SourcePathShape(NamedTuple):
    """A JSON shape whose values are file paths a webhook lists, not a probe.

    ``keys`` are the entries of an object whose value is the path (or, for an
    array shape, the list of paths). ``siblings`` are entries that must sit in
    the same object (any one of them), which is what tells a changed-file
    record from a scalar ``{"path": "x.py"}`` an attacker sends. ``containers``
    names the key an object is reached through (``commits[]`` is reached
    through ``commits``), for shapes a sibling alone does not identify.
    """

    name: str
    keys: frozenset[str]
    siblings: frozenset[str]
    containers: frozenset[str]


BENIGN_SOURCE_PATH_SHAPES: tuple[SourcePathShape, ...] = (
    SourcePathShape(
        "push change list",
        frozenset({"added", "removed", "modified"}),
        frozenset(),
        frozenset({"commits", "head_commit"}),
    ),
    SourcePathShape(
        "review comment",
        frozenset({"path"}),
        frozenset({"diff_hunk", "position"}),
        frozenset(),
    ),
    SourcePathShape(
        "pull request file",
        frozenset({"filename"}),
        frozenset({"patch", "status"}),
        frozenset(),
    ),
    SourcePathShape(
        "stack frame",
        frozenset({"filename"}),
        frozenset({"lineno", "function"}),
        frozenset({"frames"}),
    ),
)

SHAPE_KEYS: frozenset[str] = frozenset(
    key for shape in BENIGN_SOURCE_PATH_SHAPES for key in shape.keys
)

_source_path_in_benign_shape: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "guard_core_detection_source_path_in_benign_shape", default=False
)


class BenignShapePath(str):
    """A path leaf the walk found in a benign shape."""

    __slots__ = ()


class BenignShapePaths(list[Any]):
    """A list of path leaves the walk found in a benign shape."""

    __slots__ = ()


def benign_shape_keys(entries: dict[Any, Any], container: str) -> frozenset[str]:
    exempt: set[str] = set()
    for shape in BENIGN_SOURCE_PATH_SHAPES:
        if shape.containers and container not in shape.containers:
            continue
        if shape.siblings and shape.siblings.isdisjoint(entries):
            continue
        exempt.update(key for key in shape.keys if key in entries)
    return frozenset(exempt)


def mark_benign_shape(value: Any) -> Any:
    if isinstance(value, str):
        return BenignShapePath(value)
    if isinstance(value, list):
        return BenignShapePaths(value)
    return value


def source_path_leaf_in_benign_shape() -> bool:
    return _source_path_in_benign_shape.get()


def enter_benign_shape() -> contextvars.Token[bool]:
    return _source_path_in_benign_shape.set(True)


def leave_benign_shape(token: contextvars.Token[bool]) -> None:
    _source_path_in_benign_shape.reset(token)
