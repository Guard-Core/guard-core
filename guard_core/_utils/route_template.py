import re
from functools import lru_cache
from typing import NamedTuple

from guard_core._lazy_patterns import LazyPatterns, module_attribute_lookup

CONVERTER_PARAMETER_SOURCE = r"\{(\w+)(?::(\w+))?\}|<(?:(\w+)(?:\([^)]*\))?:)?(\w+)>"
_TOKEN_SOURCE = (
    rf"(?P<skipped>\\.|\[\^?\]?(?:\\.|[^\]\\])*\]|{CONVERTER_PARAMETER_SOURCE})"
    r"|(?P<named>\(\?P<(?P<group_name>\w+)>)"
    r"|(?P<unnamed>\((?!\?))"
    r"|(?P<other_group>\()"
    r"|(?P<close>\))"
)
_PATTERNS = LazyPatterns(
    {
        "CONVERTER_PARAMETER_RE": (CONVERTER_PARAMETER_SOURCE, 0),
        "_TOKEN_RE": (_TOKEN_SOURCE, re.DOTALL),
        "_ESCAPED_LITERAL_RE": (r"\\([.\-/])", 0),
        "_PLAIN_SYNTAX_RE": (r"[()\[\]{}*+?|^$\\]", 0),
        "_REGEX_SYNTAX_RE": (r"[()\[\]{}*+?|^$\\.]", 0),
    }
)
__getattr__ = module_attribute_lookup(_PATTERNS)

_TEMPLATE_CACHE_SIZE = 4096


class CaptureGroup(NamedTuple):
    start: int
    end: int
    name: str | None
    ordinal: int
    top_level: bool


class _OpenGroup(NamedTuple):
    start: int
    name: str | None
    ordinal: int | None


@lru_cache(maxsize=_TEMPLATE_CACHE_SIZE)
def capture_groups(template: str) -> tuple[CaptureGroup, ...]:
    """Every capturing group of a regex route template, in opening order.

    Tracks parenthesis depth, backslash escapes and character classes, so a
    nested group, an escaped parenthesis or a ``)`` inside ``[...]`` does not
    end a group early; a ``<conv(args):name>`` converter is skipped whole. A
    group's ``ordinal`` is its 0-based position among all captures, nested ones
    included. An unbalanced group is not reported."""
    found: list[CaptureGroup] = []
    open_groups: list[_OpenGroup] = []
    captures = 0
    for token in _PATTERNS["_TOKEN_RE"].finditer(template):
        if token["close"]:
            if open_groups:
                opened = open_groups.pop()
                if opened.ordinal is not None:
                    found.append(
                        CaptureGroup(
                            opened.start,
                            token.end(),
                            opened.name,
                            opened.ordinal,
                            not open_groups,
                        )
                    )
        elif token["skipped"] is None:
            ordinal = None
            if token["named"] or token["unnamed"]:
                ordinal = captures
                captures += 1
            open_groups.append(_OpenGroup(token.start(), token["group_name"], ordinal))
    return tuple(sorted(found, key=lambda group: group.start))


def _strip_regex_anchors(template: str) -> str:
    body = template.removeprefix("^")
    if body.endswith("$") and not body.endswith("\\$"):
        body = body[:-1]
    return body.removesuffix("/?")


def _is_regex_template(template: str) -> bool:
    without_converters = _PATTERNS["CONVERTER_PARAMETER_RE"].sub("", template)
    return (
        "(" in without_converters or template.startswith("^") or template.endswith("$")
    )


def _literal_path_text(chunk: str, is_regex: bool) -> str | None:
    converters = _PATTERNS["CONVERTER_PARAMETER_RE"]
    escaped = _PATTERNS["_ESCAPED_LITERAL_RE"]
    syntax = _PATTERNS["_REGEX_SYNTAX_RE" if is_regex else "_PLAIN_SYNTAX_RE"]
    if syntax.search(escaped.sub("", converters.sub("", chunk))):
        return None
    return str(converters.sub(r"{\1\4}", escaped.sub(r"\1", chunk)))


@lru_cache(maxsize=_TEMPLATE_CACHE_SIZE)
def normalized_route_template(template: str) -> str | None:
    """The route template as ``/orgs/{org}/old/{year}``, or None when regex syntax
    other than capture groups is left (the consumer then keeps its own form).

    Regex groups become ``{name}`` (``{0}``, ``{1}`` by capture ordinal when
    unnamed), converter syntax (``{name:conv}``, ``<conv:name>``) becomes
    ``{name}`` on the literal text that is left, ``^``, ``$`` and a trailing
    ``/?`` are dropped and ``\\.``, ``\\-``, ``\\/`` become literals. The regex
    rule applies only to a template with a group, a leading ``^`` or a trailing
    ``$``: ``files.json`` keeps its dot."""
    is_regex = _is_regex_template(template)
    body = _strip_regex_anchors(template) if is_regex else template
    pieces: list[str] = []
    position = 0
    for group in capture_groups(body):
        if not group.top_level:
            continue
        literal = _literal_path_text(body[position : group.start], is_regex)
        if literal is None:
            return None
        pieces.append(f"{literal}{{{group.name or group.ordinal}}}")
        position = group.end
    tail = _literal_path_text(body[position:], is_regex)
    if tail is None:
        return None
    path = "".join(pieces) + tail
    return path if path.startswith("/") else f"/{path}"
