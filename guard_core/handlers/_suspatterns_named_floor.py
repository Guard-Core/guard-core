import re
from collections.abc import Callable
from functools import lru_cache

from guard_core._utils.route_gate import (
    is_scanning_declared_path_param_values,
    isolate_declared_path_params,
    named_probe_is_not_the_apps_own_route,
    normalized_last_segment,
    path_probe_is_not_the_apps_own_route,
    route_declares,
)
from guard_core._utils.source_path_shapes import (
    absolute_path_leaf_in_benign_shape,
    named_file_leaf_in_benign_shape,
    source_path_leaf_in_benign_shape,
)
from guard_core.handlers._suspatterns_sources import (
    _CTX_CMS_PROBING,
    _CTX_RECON,
    _NAMED_PATH_SUFFIX_RE,
    _PATH_ONLY_CHAR_RE,
    _PATH_ONLY_SEP_RE,
    _PATH_ONLY_SUFFIX_RE,
    _PLAIN_SOURCE_OR_MAP_PATH_END_RE,
    NUL_TAIL_MARKER,
    _nested_path_pattern,
    _path_only_pattern,
    _source_extension_path_is_probe,
)

_CMS = r"(?:wp-(?:admin|login|content|includes|config)|administrator|xmlrpc)\.?(?:php)?"
_CMS_TOKENS = r"wp-(?:admin|login|content|includes|config)|administrator|xmlrpc"
_MANAGEMENT = (
    r"(?:management|config_dump|credentials|system[/\\]version|version[/\\]system)"
)
_MANAGEMENT_TOKENS = (
    r"management|config_dump|credentials|system[/\\]version|version[/\\]system"
)
_README = (
    r"(?:readme\.txt|README\.md|CHANGELOG|pom\.xml|build\.gradle"
    r"|appsettings\.json|crossdomain\.xml)"
)
_README_TOKENS = (
    r"readme\.txt|README\.md|CHANGELOG|pom\.xml|build\.gradle"
    r"|appsettings\.json|crossdomain\.xml"
)

V440_CMS_ROW = _path_only_pattern(_CMS)
V440_MANAGEMENT_ROW = _nested_path_pattern(_MANAGEMENT)
V440_SYSTEM_VERSION_ROOT_ROW = (
    rf"\A{_PATH_ONLY_SEP_RE}(?:system|version)"
    rf"(?:{_PATH_ONLY_SEP_RE}{_PATH_ONLY_CHAR_RE}*)*(?:\?\S*)?\s*\Z"
)
V440_LANGUAGE_ROW = _path_only_pattern(r"(?:language|languages)")
V440_README_ROW = _path_only_pattern(_README, r"(?:\.[\w.\-~%]*)?")
V440_INICIO_ROW = _path_only_pattern(r"inicio\.html?")

CMS_TOKEN_PATTERN = re.compile(_CMS_TOKENS, re.IGNORECASE)

NAMED_FLOOR_TOKEN_PATTERNS: dict[str, re.Pattern[str]] = {
    V440_CMS_ROW: CMS_TOKEN_PATTERN,
    V440_MANAGEMENT_ROW: re.compile(_MANAGEMENT_TOKENS, re.IGNORECASE),
    V440_SYSTEM_VERSION_ROOT_ROW: re.compile(r"system|version", re.IGNORECASE),
    V440_LANGUAGE_ROW: re.compile(r"language|languages", re.IGNORECASE),
    V440_README_ROW: re.compile(_README_TOKENS, re.IGNORECASE),
    V440_INICIO_ROW: re.compile(r"inicio\.html?", re.IGNORECASE),
}

SUPERSEDING_ROWS: dict[str, tuple[re.Pattern[str], ...]] = {}

NAMED_FLOOR_ROWS: tuple[tuple[str, frozenset[str], str], ...] = (
    (V440_CMS_ROW, _CTX_CMS_PROBING, "cms_probing"),
    (V440_MANAGEMENT_ROW, _CTX_RECON, "recon"),
    (V440_SYSTEM_VERSION_ROOT_ROW, _CTX_RECON, "recon"),
    (V440_LANGUAGE_ROW, _CTX_RECON, "recon"),
    (V440_README_ROW, _CTX_RECON, "recon"),
    (V440_INICIO_ROW, _CTX_RECON, "recon"),
)


def is_the_request_url_path(context: str) -> bool:
    return context.startswith("url_path") and _source_extension_path_is_probe(context)


def probe_lies_inside_a_declared_path_param(
    pattern: re.Pattern,
    match: re.Match,
    context: str,
    category: str,
    candidate_passes: Callable[[re.Pattern, re.Match, str], bool],
) -> bool:
    if not is_the_request_url_path(context):
        return False
    views = isolate_declared_path_params(match.string, category)
    if views is None:
        return False
    masked, isolated = views
    remaining = pattern.search(masked)
    if remaining is not None and candidate_passes(pattern, remaining, context):
        return False
    return pattern.search(isolated) is not None


def source_path_is_a_probe(match: re.Match, context: str) -> bool:
    if not _source_extension_path_is_probe(context):
        return False
    if is_the_request_url_path(context):
        return path_probe_is_not_the_apps_own_route(match.group())
    if is_scanning_declared_path_param_values():
        return "/" in match.group() or "\\" in match.group()
    return not (
        source_path_leaf_in_benign_shape()
        and _PLAIN_SOURCE_OR_MAP_PATH_END_RE.search(match.group())
    )


def absolute_path_is_a_probe(context: str) -> bool:
    return _source_extension_path_is_probe(context) and not (
        absolute_path_leaf_in_benign_shape()
    )


_NAMED_PATH_TRICK_RE = re.compile(rf";|{NUL_TAIL_MARKER}|::\$|\.\s*\Z")


def named_path_has_a_trick_suffix(path: str) -> bool:
    return _NAMED_PATH_TRICK_RE.search(path) is not None


@lru_cache(maxsize=256)
def _named_row_without_path_info(source: str, flags: int) -> re.Pattern[str]:
    for suffix in (_NAMED_PATH_SUFFIX_RE, _PATH_ONLY_SUFFIX_RE):
        if source.endswith(suffix):
            return re.compile(source.removesuffix(suffix) + r"\s*\Z", flags)
    return re.compile(source, flags)


def named_file_in_a_push_list_is_plain(pattern: re.Pattern, match: re.Match) -> bool:
    if not named_file_leaf_in_benign_shape() or named_path_has_a_trick_suffix(
        match.group()
    ):
        return False
    return (
        _named_row_without_path_info(pattern.pattern, pattern.flags).match(
            match.group()
        )
        is not None
    )


def recon_path_is_a_probe(match: re.Match, context: str) -> bool:
    if is_the_request_url_path(context):
        return path_probe_is_not_the_apps_own_route(match.group())
    return True


def _declared_tokens(source: str, match: re.Match) -> set[str]:
    path = match.group().split("?", 1)[0]
    return {
        found.lower().replace("\\", "/")
        for found in NAMED_FLOOR_TOKEN_PATTERNS[source].findall(path)
    }


def named_floor_row_is_not_the_apps_own_route(
    source: str, match: re.Match, context: str
) -> bool:
    if any(row.search(match.group()) for row in SUPERSEDING_ROWS.get(source, ())):
        return False
    if not is_the_request_url_path(context):
        return True
    tokens = _declared_tokens(source, match)
    return not tokens or not all(route_declares(token) for token in tokens)


def last_segment_is_not_the_apps_own_route(match: re.Match, context: str) -> bool:
    if not is_the_request_url_path(context):
        return True
    segment = normalized_last_segment(match.group())
    return not segment or not route_declares(segment)


def named_probe_row_is_not_the_apps_own_route(token: str, context: str) -> bool:
    return is_the_request_url_path(context) and named_probe_is_not_the_apps_own_route(
        token
    )
