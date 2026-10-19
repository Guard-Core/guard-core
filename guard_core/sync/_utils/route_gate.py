import contextvars
import re
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

ROUTE_TEMPLATE_STATE_ATTR = "guard_route_template"

FLOOR_EXTENSIONS = frozenset(
    "ts tsx jsx py rb java go rs php pl sh sql asp aspx jsp jsa jhtml shtml cfm cgi "
    "do action lua inc woa nsf esp map".split()
)

_matched_route_template: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "guard_core_matched_route_template", default=None
)
_UNESCAPED_DOT_RE = re.compile(r"\\\.|\[\.\]")
_LAST_SEGMENT_RE = re.compile(r"[^/\\]*$")


def normalized_last_segment(path: str) -> str:
    stripped = path.split("?", 1)[0].rstrip("/\\")
    segment = _LAST_SEGMENT_RE.search(stripped)
    last = segment.group() if segment else ""
    return last.split(";", 1)[0].lower()


def floor_extension_token(path: str) -> str | None:
    last = normalized_last_segment(path)
    if "." not in last:
        return None
    extension = last.rsplit(".", 1)[1]
    return f".{extension}" if extension in FLOOR_EXTENSIONS else None


_NAMED_PROBE_TOKENS = (
    "wp-admin wp-login wp-content wp-includes wp-config administrator xmlrpc "
    "management config_dump credentials system version language readme.txt "
    "readme.md changelog pom.xml build.gradle appsettings.json crossdomain.xml "
    "inicio.htm"
).split()


def might_be_a_gated_probe(path: str) -> bool:
    if floor_extension_token(path) is not None:
        return True
    lowered = path.split("?", 1)[0].lower()
    return any(token in lowered for token in _NAMED_PROBE_TOKENS)


def route_state_template(state: Any) -> str | None:
    if getattr(state, "guard_route_unresolved", False) is True:
        return None
    template = getattr(state, ROUTE_TEMPLATE_STATE_ATTR, None)
    return template if isinstance(template, str) else None


@contextmanager
def route_knowledge(template: str | None) -> Iterator[None]:
    token = _matched_route_template.set(template)
    try:
        yield
    finally:
        _matched_route_template.reset(token)


def route_declares(probe_token: str) -> bool:
    template = _matched_route_template.get()
    if template is None:
        return False
    return probe_token.lower() in _UNESCAPED_DOT_RE.sub(".", template).lower()


def path_probe_is_not_the_apps_own_route(path: str) -> bool:
    token = floor_extension_token(path)
    return token is None or not route_declares(token)


def named_probe_is_not_the_apps_own_route(token: str) -> bool:
    return not route_declares(token)
