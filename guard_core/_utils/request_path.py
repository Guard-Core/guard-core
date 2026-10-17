import re


def resolve_dot_and_empty_segments(url_path: str) -> str:
    segments: list[str] = []
    for segment in url_path.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    resolved = "/" + "/".join(segments)
    if url_path.endswith("/") and resolved != "/":
        resolved += "/"
    return resolved


_ENCODED_DOT_OR_SEPARATOR = re.compile(r"%(?:2e|2f|5c)", re.IGNORECASE)


def _is_dot_segment(segment: str) -> bool:
    return segment.split(";", 1)[0] in (".", "..")


def has_routing_anomaly(url_path: str) -> bool:
    if "\\" in url_path or _ENCODED_DOT_OR_SEPARATOR.search(url_path):
        return True
    segments = url_path.split("/")[1:]
    if segments and segments[-1] == "":
        segments.pop()
    return any(segment == "" or _is_dot_segment(segment) for segment in segments)


_ANOMALOUS_SPELLING = re.compile(r"\.\.|//|\\|%(?:2f|5c)", re.IGNORECASE)


def has_anomalous_path_spelling(path: str) -> bool:
    return _ANOMALOUS_SPELLING.search(path) is not None
