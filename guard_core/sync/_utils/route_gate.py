import contextvars
import logging
import re
from collections.abc import Collection, Iterator, Mapping
from contextlib import contextmanager
from functools import lru_cache
from types import MappingProxyType

from guard_core._lazy_patterns import LazyPatterns, module_attribute_lookup
from guard_core._misconfiguration_kinds import (
    K_DETECTION_EXCLUSION_PARAM_NOT_IN_TEMPLATE,
    K_DETECTION_EXCLUSION_PARAM_WITHOUT_LITERAL_SEGMENT,
    K_ROUTE_UNKNOWN_TO_DECORATOR,
    Problem,
)
from guard_core.sync._utils.route_template import (
    CONVERTER_PARAMETER_SOURCE,
    capture_groups,
    normalized_route_template,
)
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

ROUTE_TEMPLATE_STATE_ATTR = "guard_route_template"
ROUTE_TEMPLATE_EVENT_FIELD = "route_template"
STATIC_FILE_STATE_ATTR = "guard_static_file_served"
STATIC_FILE_EXTENSIONS = frozenset({"ts", "map"})

FLOOR_EXTENSIONS = frozenset(
    "ts tsx jsx py rb java go rs php pl sh sql asp aspx jsp jsa jhtml shtml cfm cgi "
    "do action lua inc woa nsf esp map phtml php3 php4 php5 php6 php7 php8 pht phps "
    "phar asa cer ashx asmx ascx".split()
)

_matched_route_template: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "guard_core_matched_route_template", default=None
)
_static_file_served: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "guard_core_static_file_served", default=False
)
declared_path_params_var: contextvars.ContextVar[Mapping[str, frozenset[str]]] = (
    contextvars.ContextVar(
        "guard_core_declared_path_params", default=MappingProxyType({})
    )
)
_declared_path_param_value_scan: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "guard_core_declared_path_param_value_scan", default=False
)
PATH_PARAM_DEFAULT_CATEGORIES = frozenset({"recon", "cms_probing"})


def normalized_last_segment(path: str) -> str:
    stripped = path.split("?", 1)[0].rstrip("/\\")
    last = stripped.rpartition("/")[2].rpartition("\\")[2]
    return last.split(";", 1)[0].lower()


def floor_extension_token(path: str) -> str | None:
    last = normalized_last_segment(path)
    if "." not in last:
        return None
    extension = last.rsplit(".", 1)[1]
    return f".{extension}" if extension in FLOOR_EXTENSIONS else None


def might_be_a_static_file(path: str) -> bool:
    last = normalized_last_segment(path)
    return "." in last and last.rsplit(".", 1)[1] in STATIC_FILE_EXTENSIONS


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


def route_state_template(state: object) -> str | None:
    if getattr(state, "guard_route_unresolved", False) is True:
        return None
    template = getattr(state, ROUTE_TEMPLATE_STATE_ATTR, None)
    return template if isinstance(template, str) else None


def static_file_state_served(state: object) -> bool:
    return getattr(state, STATIC_FILE_STATE_ATTR, False) is True


@contextmanager
def route_knowledge(
    template: str | None,
    static_file_served: bool = False,
    declared_path_params: Mapping[str, frozenset[str]] | None = None,
) -> Iterator[None]:
    template_token = _matched_route_template.set(template)
    static_token = _static_file_served.set(static_file_served)
    declared_token = declared_path_params_var.set(
        _without_root_captures(template, declared_path_params or {})
    )
    try:
        yield
    finally:
        declared_path_params_var.reset(declared_token)
        _static_file_served.reset(static_token)
        _matched_route_template.reset(template_token)


@lru_cache(maxsize=4096)
def _root_capture_names(template: str, names: tuple[str, ...]) -> frozenset[str]:
    return frozenset(path_params_without_a_literal_segment_before(template, names))


def _without_root_captures(
    template: str | None, declared: Mapping[str, frozenset[str]]
) -> Mapping[str, frozenset[str]]:
    # a name with no literal segment before it would exempt the whole path, so the
    # path is scanned in full instead (the safe side)
    if template is None or not declared:
        return declared
    rootless = _root_capture_names(template, tuple(declared))
    return {name: kept for name, kept in declared.items() if name not in rootless}


def route_declares(probe_token: str) -> bool:
    template = _matched_route_template.get()
    if template is None:
        return False
    literal = _PATTERNS["_PARAMETER_RE"].sub("/", template)
    return (
        probe_token.lower() in _PATTERNS["_UNESCAPED_DOT_RE"].sub(".", literal).lower()
    )


def path_probe_is_not_the_apps_own_route(path: str) -> bool:
    token = floor_extension_token(path)
    if token is None:
        return True
    if token[1:] in STATIC_FILE_EXTENSIONS and _static_file_served.get():
        return False
    return not route_declares(token)


def named_probe_is_not_the_apps_own_route(token: str) -> bool:
    return not route_declares(token)


_CATCH_ALL_CONVERTER = "path"


@lru_cache(maxsize=4096)
def _template_matcher(template: str) -> re.Pattern[str] | None:
    if "(?P<" in template:
        pattern = template
    else:
        pieces: list[str] = []
        position = 0
        for found in _PATTERNS["_STARLETTE_OR_ANGLE_PARAMETER_RE"].finditer(template):
            pieces.append(re.escape(template[position : found.start()]))
            converter = found.group(2) or found.group(3)
            inner = ".*" if converter == _CATCH_ALL_CONVERTER else "[^/]+"
            pieces.append(f"(?P<{found.group(1) or found.group(4)}>{inner})")
            position = found.end()
        pieces.append(re.escape(template[position:]))
        pattern = "".join(pieces) + r"/?\Z"
    try:
        return re.compile(pattern)
    except re.error:
        return None


def _match_the_template(view: str) -> tuple[re.Match[str], int] | None:
    template = _matched_route_template.get()
    matcher = _template_matcher(template) if template is not None else None
    if matcher is None:
        return None
    path = view.split("?", 1)[0]
    for offset in (0, 1) if path.startswith("/") else (0,):
        found = matcher.match(path[offset:])
        if found is not None:
            return found, offset
    return None


def declared_path_param_spans(
    view: str, category: str | None = None
) -> dict[str, tuple[int, int]]:
    declared = declared_path_params_var.get()
    matched = _match_the_template(view) if declared else None
    if matched is None:
        return {}
    found, offset = matched
    spans: dict[str, tuple[int, int]] = {}
    for name, categories in declared.items():
        if (category is None or category in categories) and name in found.re.groupindex:
            start, end = found.span(name)
            if start != -1:
                spans[name] = (start + offset, end + offset)
    return spans


def isolate_declared_path_params(view: str, category: str) -> tuple[str, str] | None:
    spans = declared_path_param_spans(view, category)
    if not spans:
        return None
    masked = view
    for start, end in spans.values():
        masked = f"{masked[:start]}{'a' * (end - start)}{masked[end:]}"
    query_start = view.find("?")
    if query_start == -1:
        query_start = len(view)
    inside = [
        char
        if char in "/\\" or any(start <= index < end for start, end in spans.values())
        else "a"
        for index, char in enumerate(view[:query_start])
    ]
    return masked, "".join(inside) + view[query_start:]


@contextmanager
def scanning_declared_path_param_values() -> Iterator[None]:
    token = _declared_path_param_value_scan.set(True)
    try:
        yield
    finally:
        _declared_path_param_value_scan.reset(token)


def is_scanning_declared_path_param_values() -> bool:
    return _declared_path_param_value_scan.get()


def declared_path_param_values(view: str) -> list[tuple[str, str]]:
    return [
        (name, view[start:end])
        for name, (start, end) in declared_path_param_spans(view).items()
    ]


_PATTERNS = LazyPatterns(
    {
        "_UNESCAPED_DOT_RE": (r"\\\.|\[\.\]", 0),
        "_PARAMETER_RE": (r"\{[^}]*\}|<[^>]*>", 0),
        "_STARLETTE_OR_ANGLE_PARAMETER_RE": (CONVERTER_PARAMETER_SOURCE, 0),
    }
)
__getattr__ = module_attribute_lookup(_PATTERNS)


def _text_before_without_captures(template: str, end: int) -> str:
    kept: list[str] = []
    position = 0
    for group in capture_groups(template):
        if group.top_level and group.end <= end:
            kept.append(template[position : group.start])
            position = group.end
    kept.append(template[position:end])
    return "".join(kept)


def _declared_name_start(template: str, name: str) -> int | None:
    group = next(
        (found for found in capture_groups(template) if found.name == name), None
    )
    if group is not None:
        return group.start
    found = next(
        (
            candidate
            for candidate in _PATTERNS["_STARLETTE_OR_ANGLE_PARAMETER_RE"].finditer(
                template
            )
            if name in (candidate.group(1), candidate.group(4))
        ),
        None,
    )
    return None if found is None else found.start()


def path_params_missing_from_template(
    template: str, declared: Collection[str]
) -> list[str]:
    return [name for name in declared if _declared_name_start(template, name) is None]


def path_params_without_a_literal_segment_before(
    template: str, declared: Collection[str]
) -> list[str]:
    rootless = []
    for name in declared:
        start = _declared_name_start(template, name)
        if start is None:
            continue
        prefix = _PATTERNS["_STARLETTE_OR_ANGLE_PARAMETER_RE"].sub(
            "", _text_before_without_captures(template, start)
        )
        if not re.search(r"[^/^]", prefix):
            rootless.append(name)
    return rootless


def declared_path_param_problems(
    template: str, declared: Collection[str]
) -> dict[str, str]:
    return {
        name: (
            f"has no literal segment before it in the route template "
            f"{template!r}: it would exempt the whole path from the probe "
            "rows, so the whole path is scanned."
        )
        for name in path_params_without_a_literal_segment_before(template, declared)
    } | {
        name: f"is not in the route template {template!r}, so it exempts nothing."
        for name in path_params_missing_from_template(template, declared)
    }


def detection_exclusion_path_param_problems(
    route_id: str, template: str, declared: Collection[str]
) -> list[Problem]:
    """The kinded problems of one route's ``@detection_exclusion(path_params=...)``.

    Every adapter reports these through this one helper, so the text and the kind
    are the same in every framework. The subject is the declared parameter name.
    """
    rootless = set(path_params_without_a_literal_segment_before(template, declared))
    problems = []
    for name, text in declared_path_param_problems(template, declared).items():
        kind = (
            K_DETECTION_EXCLUSION_PARAM_WITHOUT_LITERAL_SEGMENT
            if name in rootless
            else K_DETECTION_EXCLUSION_PARAM_NOT_IN_TEMPLATE
        )
        problems.append(
            Problem(
                f"@detection_exclusion(path_params=...) on route {route_id!r} "
                f"declares {name!r}, which {text}",
                kind=kind,
                subject=name,
            )
        )
    return problems


def route_unknown_to_decorator_problem(route_label: str) -> Problem:
    """The kinded problem of a route stamped by a SecurityDecorator other than the
    one the middleware uses. Every adapter and the engine's resolver report it
    through this one helper, so the text and the kind are the same everywhere."""
    return Problem(
        f"Route {route_label!r} carries a route id that this SecurityDecorator does "
        "not know: it was decorated by a different SecurityDecorator instance "
        "than the one the middleware uses, so none of its decorators apply. "
        "Decorate the route with the SecurityDecorator the middleware uses.",
        kind=K_ROUTE_UNKNOWN_TO_DECORATOR,
        subject=route_label,
    )


def route_template_event_fields(state: object) -> dict[str, str]:
    """``{"route_template": ...}`` for a request-bound event when the request has
    one the consumer can use (see ``normalized_route_template``), else ``{}``."""
    raw = route_state_template(state)
    template = normalized_route_template(raw) if raw is not None else None
    return {} if template is None else {ROUTE_TEMPLATE_EVENT_FIELD: template}


def metric_route_template(state: object) -> str | None:
    """The endpoint tag for a metric: the normalised template, the raw one when
    regex syntax is left in it, None when the request matched no route."""
    raw = route_state_template(state)
    if raw is None:
        return None
    return normalized_route_template(raw) or raw


def record_route_template(
    request: SyncGuardRequest, middleware: object, logger: logging.Logger
) -> None:
    """Ask the middleware for the request's template once and keep the raw
    answer on the state; a request an adapter stamped, or one that matched no
    route, is left alone."""
    state = request.state
    if getattr(state, ROUTE_TEMPLATE_STATE_ATTR, None) is not None:
        return
    if getattr(state, "guard_route_unresolved", False) is True:
        return
    lookup = getattr(middleware, "route_template", None)
    if not callable(lookup):
        return
    try:
        template = lookup(str(request.url_path))
    except Exception:
        logger.error("route_template failed; the path is judged without it")
        return
    if isinstance(template, str):
        setattr(state, ROUTE_TEMPLATE_STATE_ATTR, template)
