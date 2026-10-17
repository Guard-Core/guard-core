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
