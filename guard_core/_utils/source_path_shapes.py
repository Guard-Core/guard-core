import contextvars
import re
from collections.abc import Iterator, Mapping
from typing import NamedTuple


class SourcePathShape(NamedTuple):
    """A JSON shape whose values are file paths a webhook lists, not a probe.

    ``keys`` are the entries of an object whose value is the path (or, for an
    array shape, the list of paths). ``siblings`` are entries that must sit in
    the same object (any one of them), which is what tells a changed-file
    record from a scalar ``{"path": "x.py"}`` an attacker sends. ``containers``
    names the key an object is reached through (``commits[]`` is reached
    through ``commits``), for shapes a sibling alone does not identify.
    ``grants`` names which probe rows the shape clears for its paths: the source
    extension and source map rows (``SOURCE``), the named file rows such as
    ``config/settings.py`` or ``.env.example`` (``NAMED_FILES``) and the absolute
    path row (``ABSOLUTE_PATH``).
    """

    name: str
    keys: frozenset[str]
    siblings: frozenset[str]
    containers: frozenset[str]
    grants: frozenset[str]


SOURCE = "source"
NAMED_FILES = "named_files"
ABSOLUTE_PATH = "absolute_path"


BENIGN_SOURCE_PATH_SHAPES: tuple[SourcePathShape, ...] = (
    SourcePathShape(
        "push change list",
        frozenset({"added", "removed", "modified"}),
        frozenset(),
        frozenset({"commits", "head_commit"}),
        frozenset({SOURCE, NAMED_FILES}),
    ),
    SourcePathShape(
        "review comment",
        frozenset({"path"}),
        frozenset({"diff_hunk", "position"}),
        frozenset(),
        frozenset({SOURCE, NAMED_FILES}),
    ),
    SourcePathShape(
        "pull request file",
        frozenset({"filename"}),
        frozenset({"patch", "status"}),
        frozenset(),
        frozenset({SOURCE, NAMED_FILES}),
    ),
    SourcePathShape(
        "stack frame",
        frozenset({"filename"}),
        frozenset({"lineno", "function"}),
        frozenset({"frames"}),
        frozenset({SOURCE, NAMED_FILES}),
    ),
    SourcePathShape(
        "stack frame absolute path",
        frozenset({"abs_path"}),
        frozenset({"lineno", "function"}),
        frozenset({"frames"}),
        frozenset({SOURCE, ABSOLUTE_PATH}),
    ),
)

SHAPE_KEYS: frozenset[str] = frozenset(
    key for shape in BENIGN_SOURCE_PATH_SHAPES for key in shape.keys
)

_benign_shape_grants: contextvars.ContextVar[frozenset[str]] = contextvars.ContextVar(
    "guard_core_detection_benign_shape_grants", default=frozenset()
)


class BenignShapePath(str):
    """A path leaf the walk found in a benign shape, with the rows it clears."""

    __slots__ = ("grants",)
    grants: frozenset[str]


class BenignShapePaths(list[object]):
    """A list of path leaves the walk found in a benign shape."""

    __slots__ = ("grants",)
    grants: frozenset[str]


def _applicable_shapes(
    entries: Mapping[str, object], container: str
) -> Iterator[SourcePathShape]:
    for shape in BENIGN_SOURCE_PATH_SHAPES:
        if shape.containers and container not in shape.containers:
            continue
        if shape.siblings and shape.siblings.isdisjoint(entries):
            continue
        yield shape


def benign_shape_keys(entries: Mapping[str, object], container: str) -> frozenset[str]:
    exempt: set[str] = set()
    for shape in _applicable_shapes(entries, container):
        exempt.update(key for key in shape.keys if key in entries)
    return frozenset(exempt)


def benign_shape_grants(
    entries: Mapping[str, object], container: str
) -> dict[str, frozenset[str]]:
    granted: dict[str, frozenset[str]] = {}
    for shape in _applicable_shapes(entries, container):
        for key in shape.keys:
            if key in entries:
                granted[key] = granted.get(key, frozenset()) | shape.grants
    return granted


# Relative, with no "." or ".." segment, no encoding, no separator or suffix trick:
# the shape of a file name a push lists, which a traversal, an absolute path or a
# trick suffix such as ";.jpg" or "%00" is not. An editor backup ends in one "~".
_PLAIN_RELATIVE_FILE_PATH_RE = re.compile(
    r"(?:(?!\.\.?/)[\w.\-]+/)*(?!\.\.?\s*\Z)[\w.\-]+~?\s*\Z"
)


def mark_benign_shape_path(path: str, grants: frozenset[str]) -> BenignShapePath:
    marked = BenignShapePath(path)
    marked.grants = (
        grants
        if NAMED_FILES not in grants or _PLAIN_RELATIVE_FILE_PATH_RE.match(path)
        else grants - {NAMED_FILES}
    )
    return marked


def mark_benign_shape(value: object, grants: frozenset[str]) -> object:
    if isinstance(value, str):
        return mark_benign_shape_path(value, grants)
    if isinstance(value, list):
        marked_list = BenignShapePaths(value)
        marked_list.grants = grants
        return marked_list
    return value


def source_path_leaf_in_benign_shape() -> bool:
    return SOURCE in _benign_shape_grants.get()


def named_file_leaf_in_benign_shape() -> bool:
    return NAMED_FILES in _benign_shape_grants.get()


def absolute_path_leaf_in_benign_shape() -> bool:
    return ABSOLUTE_PATH in _benign_shape_grants.get()


def enter_benign_shape(grants: frozenset[str]) -> contextvars.Token[frozenset[str]]:
    return _benign_shape_grants.set(grants)


def leave_benign_shape(token: contextvars.Token[frozenset[str]]) -> None:
    _benign_shape_grants.reset(token)
