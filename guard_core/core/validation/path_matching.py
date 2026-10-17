import re
from collections.abc import Sequence

_PERCENT_RUN = re.compile(r"(?:%[0-9A-Fa-f]{2})+")
_MAX_DECODE_ROUNDS = 4


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


def _collapse_dot_segments(decoded: str) -> str | None:
    segments: list[str] = []
    for raw_segment in decoded.replace("\\", "/").split("/"):
        segment = _fold_dot_segment_params(raw_segment)
        if segment in ("", "."):
            continue
        if segment == "..":
            return None
        segments.append(segment)
    return "/" + "/".join(segments)


def normalize_url_path(raw_path: str) -> str | None:
    decoded = _decode_percent_recursive(raw_path)
    if decoded is None:
        return None
    return _collapse_dot_segments(decoded)


def _is_subtree_or_equal(path: str, excluded: str) -> bool:
    if excluded == "/":
        return True
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


def path_is_excluded(url_path: str, exclude_paths: Sequence[str]) -> bool:
    normalized_path = normalize_url_path(url_path)
    if normalized_path is None:
        return False
    return path_matches_exclusions(
        normalized_path, normalize_exclude_paths(exclude_paths)
    )
