import re
from collections.abc import Sequence

from guard_core._utils.request_path import has_routing_anomaly

_PERCENT_RUN = re.compile(r"(?:%[0-9A-Fa-f]{2})+")
_MAX_DECODE_ROUNDS = 4
# {name} or {name:conv} (Starlette, Go net/http, axum, actix), <name> or <conv:name>
# (Flask, Django path(), Rocket), "/:name" (Express, Fastify, Hono, NestJS, Gin, Echo,
# Fiber), (?P<name>...) (Tornado, Django re_path): a router matches the key like a
# request. A regex route counts too, as RFC 3986 pchar has no "[", "]", "^", "|", "?"
# or backslash: a "[...]" class, a leading "^", a "(...)" group holding backslash,
# + * ? or |, or a bare ".+". A word in parentheses ("/Foo_(bar)"), a trailing "$" and
# a colon inside a segment ("/gpt:generate") are pchars. A "*" is a glob.
_ROUTER_TEMPLATE = re.compile(
    r"\{[^{}]+\}|<[^<>]+>|/:[^/]|[\[\]]|^\^|\.\+|\([^()]*[\\+*?|][^()]*\)"
)
GLOB_CHARACTERS = "*?#"


def has_glob_character(entry: str, characters: str = GLOB_CHARACTERS) -> bool:
    return any(char in entry for char in characters)


def _decode_percent_run(match: re.Match[str]) -> str:
    raw = bytes.fromhex(match.group(0).replace("%", ""))
    return raw.decode("utf-8")


def _decode_percent_once(value: str) -> str | None:
    try:
        return _PERCENT_RUN.sub(_decode_percent_run, value)
    except UnicodeDecodeError:
        return None


def _decode_percent_recursive(raw_path: str) -> str | None:
    decoded = raw_path
    for _ in range(_MAX_DECODE_ROUNDS):
        next_decoded = _decode_percent_once(decoded)
        if next_decoded is None:
            return None
        decoded = next_decoded
    if _PERCENT_RUN.search(decoded):
        return None
    return decoded


def _fold_dot_segment_params(segment: str) -> str:
    base = segment.split(";", 1)[0]
    return base if base in (".", "..") else segment


def _collapse_dot_segments(decoded: str) -> str:
    segments: list[str] = []
    for raw_segment in decoded.replace("\\", "/").split("/"):
        segment = _fold_dot_segment_params(raw_segment)
        if segment in ("", "."):
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    return "/" + "/".join(segments)


def normalize_url_path(raw_path: str) -> str | None:
    decoded = _decode_percent_recursive(raw_path)
    if decoded is None:
        return None
    return _collapse_dot_segments(decoded)


def _is_subtree_or_equal(path: str, excluded: str) -> bool:
    return path == excluded or path.startswith(excluded + "/")


def normalize_exclude_paths(exclude_paths: Sequence[str]) -> tuple[str, ...]:
    normalized = (normalize_url_path(entry) for entry in exclude_paths)
    return tuple(entry for entry in normalized if entry is not None)


def path_matches_exclusions(
    normalized_path: str, normalized_exclusions: Sequence[str]
) -> bool:
    return any(
        _is_subtree_or_equal(normalized_path, excluded)
        for excluded in normalized_exclusions
    )


def _has_routing_anomaly_in_any_decoding(url_path: str) -> bool:
    decoded: str | None = url_path
    for _ in range(_MAX_DECODE_ROUNDS + 1):
        if decoded is None or has_routing_anomaly(decoded):
            return True
        next_decoded = _decode_percent_once(decoded)
        if next_decoded == decoded:
            return False
        decoded = next_decoded
    return True


def is_router_template(key: str) -> bool:
    return _ROUTER_TEMPLATE.search(key) is not None or has_glob_character(key, "*")


def router_path_for_exclusion(url_path: str) -> str | None:
    if _has_routing_anomaly_in_any_decoding(url_path):
        return None
    return url_path.rstrip("/") or "/"


def path_is_excluded(url_path: str, exclude_paths: Sequence[str]) -> bool:
    normalized_path = router_path_for_exclusion(url_path)
    if normalized_path is None:
        return False
    return path_matches_exclusions(
        normalized_path, normalize_exclude_paths(exclude_paths)
    )
