import re

from guard_core.detection_engine.scan_window import bounded_finditer

_FILE_UPLOAD_SERVER_CONFIG_EXTENSIONS = frozenset({"htaccess", "htpasswd", "inc"})
_FILE_UPLOAD_SERVER_CONFIG_NAME_ALTERNATION = r"web\.config|\.user\.ini"
_FILE_UPLOAD_WINDOWS_SAVE_SUFFIX_RE = r"(?:[. ]*::\$DATA)?[. ]*"
_FILE_UPLOAD_DANGEROUS_EXTENSIONS = _FILE_UPLOAD_SERVER_CONFIG_EXTENSIONS | frozenset(
    {
        "phar",
        "phtml",
        "pht",
        "exe",
        "jsp",
        "jspx",
        "aspx",
        "asp",
        "asa",
        "asax",
        "ascx",
        "ashx",
        "asmx",
        "cer",
        "phps",
        "shtml",
        "cfm",
        "cfc",
        "war",
        "bash",
        "sh",
        "rb",
        "py",
        "pl",
        "cgi",
        "com",
        "bat",
        "cmd",
        "vbs",
        "vbe",
        "js",
        "ws",
        "wsf",
        "msi",
        "hta",
    }
)
_FILE_UPLOAD_DANGEROUS_EXT_ALTERNATION = r"php\d*|" + "|".join(
    re.escape(ext)
    for ext in sorted(_FILE_UPLOAD_DANGEROUS_EXTENSIONS, key=lambda c: (-len(c), c))
)
_FILE_UPLOAD_DOUBLE_EXT_EXTENSIONS = (
    _FILE_UPLOAD_DANGEROUS_EXTENSIONS
    - _FILE_UPLOAD_SERVER_CONFIG_EXTENSIONS
    - frozenset({"com"})
)
_FILE_UPLOAD_DOUBLE_EXT_ALTERNATION = r"php\d*|" + "|".join(
    re.escape(ext)
    for ext in sorted(_FILE_UPLOAD_DOUBLE_EXT_EXTENSIONS, key=lambda c: (-len(c), c))
)
_FILE_UPLOAD_BENIGN_TERMINAL_EXTENSIONS = frozenset(
    {
        "jpg",
        "jpeg",
        "png",
        "gif",
        "bmp",
        "webp",
        "svg",
        "ico",
        "tif",
        "tiff",
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "odt",
        "mp3",
        "mp4",
        "avi",
        "mov",
        "wav",
        "webm",
        "mkv",
    }
)
_FILE_UPLOAD_BENIGN_TERMINAL_ALTERNATION = "|".join(
    re.escape(ext)
    for ext in sorted(
        _FILE_UPLOAD_BENIGN_TERMINAL_EXTENSIONS, key=lambda c: (-len(c), c)
    )
)
_FILE_UPLOAD_NULL_OR_SEPARATOR_TRUNCATION_RE = r"(?:%00|\\u0000|\\x00|\\0|\x00|;)"
_FILE_UPLOAD_ATTR_EQUALS_WHITESPACE_RE = r"\s*"
_FILE_UPLOAD_FILENAME_EQUALS_RE = (
    r"(?:\A|[;,:\n])"
    + _FILE_UPLOAD_ATTR_EQUALS_WHITESPACE_RE
    + r"filename"
    + _FILE_UPLOAD_ATTR_EQUALS_WHITESPACE_RE
    + r"="
    + _FILE_UPLOAD_ATTR_EQUALS_WHITESPACE_RE
)
_FILE_UPLOAD_DOUBLE_EXTENSION_RE = (
    _FILE_UPLOAD_FILENAME_EQUALS_RE
    + r"[\"'][^\"']*\.(?:"
    + _FILE_UPLOAD_DOUBLE_EXT_ALTERNATION
    + r")(?![A-Za-z0-9])(?:[^ \"'][^\"']*)?\.(?:"
    + _FILE_UPLOAD_BENIGN_TERMINAL_ALTERNATION
    + r")"
    + _FILE_UPLOAD_WINDOWS_SAVE_SUFFIX_RE
    + r"[\"']"
)
_FILE_UPLOAD_TRUNCATION_RE = (
    _FILE_UPLOAD_FILENAME_EQUALS_RE
    + r"[\"'][^\"']*\.(?:"
    + _FILE_UPLOAD_DOUBLE_EXT_ALTERNATION
    + r")(?![A-Za-z0-9])(?:"
    + _FILE_UPLOAD_NULL_OR_SEPARATOR_TRUNCATION_RE
    + r"[^\"']*|\.)[\"']"
)
_FILE_UPLOAD_DECODED_TRUNCATION_RE = (
    _FILE_UPLOAD_FILENAME_EQUALS_RE
    + r"[\"'][^\"']*\.(?:"
    + _FILE_UPLOAD_DOUBLE_EXT_ALTERNATION
    + r")(?![A-Za-z0-9])(?:(?:\x00|;)[^\"']*|\.)[\"']"
)
_FILE_UPLOAD_DANGEROUS_EXTENSION_RE = (
    _FILE_UPLOAD_FILENAME_EQUALS_RE
    + r"[\"'](?:[^\"']*\.(?:"
    + _FILE_UPLOAD_DANGEROUS_EXT_ALTERNATION
    + r")|(?:[^\"']*[/\\])?(?:"
    + _FILE_UPLOAD_SERVER_CONFIG_NAME_ALTERNATION
    + r"))"
    + _FILE_UPLOAD_WINDOWS_SAVE_SUFFIX_RE
    + r"[\"']"
)


def _file_upload_scan_window(content: str) -> str:
    return content[: max(content.rfind('"'), content.rfind("'")) + 1]


_FILE_UPLOAD_DOUBLE_EXT_PREFIX_RE = re.compile(r"filename\s*=\s*[\"']", re.IGNORECASE)
_FILE_UPLOAD_QUOTE_RE = re.compile(r"[\"']")
_FILE_UPLOAD_FILENAME_TOKEN_RE = re.compile(r"filename", re.IGNORECASE)
_FILE_UPLOAD_DANGEROUS_EXTENSION_MARKER_RE = re.compile(
    r"\.(?:" + _FILE_UPLOAD_DOUBLE_EXT_ALTERNATION + r")(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_FILE_UPLOAD_BENIGN_TERMINAL_EXTENSION_RE = re.compile(
    r"\.(?:" + _FILE_UPLOAD_BENIGN_TERMINAL_ALTERNATION + r")\Z", re.IGNORECASE
)
_FILE_UPLOAD_DANGEROUS_TERMINAL_EXTENSION_RE = re.compile(
    r"(?:\.(?:"
    + _FILE_UPLOAD_DANGEROUS_EXT_ALTERNATION
    + r")|(?:\A|[/\\])(?:"
    + _FILE_UPLOAD_SERVER_CONFIG_NAME_ALTERNATION
    + r"))\Z",
    re.IGNORECASE,
)
_FILE_UPLOAD_NTFS_STREAM_SUFFIX_RE = re.compile(r"::\$DATA\Z", re.IGNORECASE)
_FILE_UPLOAD_NAME_TERMINATORS = " \t\r\n\x0b\x0c;,"
_FILE_UPLOAD_NAME_MAX_LENGTH = 255
_FILE_UPLOAD_TRUNCATION_MARKER_RE = re.compile(
    r"(?:%00|\\u0000|\\x00|\\0|\x00|;|\.\Z)", re.IGNORECASE
)
_FILE_UPLOAD_DECODED_TRUNCATION_MARKER_RE = re.compile(r"(?:\x00|;|\.\Z)")


_FILE_UPLOAD_VALIDATED_SPAN_RE = re.compile(r".*", re.DOTALL)


def _file_upload_match_start(content: str, filename_start: int) -> int | None:
    cursor = filename_start - 1
    first_newline = -1
    while cursor >= 0 and content[cursor].isspace():
        if content[cursor] == "\n":
            first_newline = cursor
        cursor -= 1
    if cursor == -1:
        return 0
    if content[cursor] in ";,:\n":
        return cursor
    return first_newline if first_newline != -1 else None


def _file_upload_skip_whitespace(content: str, cursor: int) -> int:
    while cursor < len(content) and content[cursor].isspace():
        cursor += 1
    return cursor


def _file_upload_quoted_candidate(
    content: str, filename_start: int
) -> tuple[int, int, int] | None:
    match_start = _file_upload_match_start(content, filename_start)
    if match_start is None:
        return None
    cursor = _file_upload_skip_whitespace(content, filename_start + len("filename"))
    if cursor == len(content) or content[cursor] != "=":
        return None
    cursor = _file_upload_skip_whitespace(content, cursor + 1)
    if cursor == len(content) or content[cursor] not in "\"'":
        return None
    body_start = cursor + 1
    quote = _FILE_UPLOAD_QUOTE_RE.search(content, body_start)
    if quote is None:
        return None
    return match_start, body_start, quote.end()


def _file_upload_is_double_extension(body: str) -> bool:
    if _FILE_UPLOAD_BENIGN_TERMINAL_EXTENSION_RE.search(body) is None:
        return False
    final_dot = body.rfind(".")
    for dangerous in _FILE_UPLOAD_DANGEROUS_EXTENSION_MARKER_RE.finditer(
        body, 0, final_dot
    ):
        suffix_start = dangerous.end()
        if suffix_start == final_dot or (
            suffix_start < final_dot and body[suffix_start] not in " \"'"
        ):
            return True
    return False


def _file_upload_is_truncation(body: str, decoded: bool) -> bool:
    marker = (
        _FILE_UPLOAD_DECODED_TRUNCATION_MARKER_RE
        if decoded
        else _FILE_UPLOAD_TRUNCATION_MARKER_RE
    )
    for dangerous in _FILE_UPLOAD_DANGEROUS_EXTENSION_MARKER_RE.finditer(body):
        if marker.match(body, dangerous.end()):
            return True
    return False


def _file_upload_windows_name(body: str) -> str:
    name = _FILE_UPLOAD_NTFS_STREAM_SUFFIX_RE.sub(
        "", body.replace('"', ".").rstrip(". ")
    )
    return name.rstrip(". ")


def _file_upload_inner_quote_end(content: str, body_start: int, end: int) -> int | None:
    close = end - 1
    while content[close + 1 : close + 2] not in _FILE_UPLOAD_NAME_TERMINATORS:
        quote = _FILE_UPLOAD_QUOTE_RE.search(content, close + 1)
        if quote is None or quote.start() - body_start > _FILE_UPLOAD_NAME_MAX_LENGTH:
            return None
        close = quote.start()
    return close + 1


def _file_upload_kind_matches(body: str, source: str) -> bool:
    spellings = (
        (body, _file_upload_windows_name(body))
        if body[-1:] in (".", " ") or "::" in body or '"' in body
        else (body,)
    )
    for spelling in spellings:
        if source == _FILE_UPLOAD_DANGEROUS_EXTENSION_RE:
            matched = (
                _FILE_UPLOAD_DANGEROUS_TERMINAL_EXTENSION_RE.search(spelling)
                is not None
            )
        elif source == _FILE_UPLOAD_DOUBLE_EXTENSION_RE:
            matched = _file_upload_is_double_extension(spelling)
        elif source == _FILE_UPLOAD_TRUNCATION_RE:
            matched = _file_upload_is_truncation(spelling, decoded=False)
        elif source == _FILE_UPLOAD_DECODED_TRUNCATION_RE:
            matched = _file_upload_is_truncation(spelling, decoded=True)
        else:
            matched = False
        if matched:
            return True
    return False


def _file_upload_scan_matches(content: str, compiled: re.Pattern) -> list[re.Match]:
    matches = []
    last_end = 0
    for filename in _FILE_UPLOAD_FILENAME_TOKEN_RE.finditer(content):
        candidate = _file_upload_quoted_candidate(content, filename.start())
        if candidate is None:
            continue
        start, body_start, end = candidate
        if start < last_end:
            continue
        if not _file_upload_kind_matches(
            content[body_start : end - 1], compiled.pattern
        ):
            inner_end = (
                None
                if content[end : end + 1] in _FILE_UPLOAD_NAME_TERMINATORS
                else _file_upload_inner_quote_end(content, body_start, end)
            )
            if inner_end is None or not _file_upload_kind_matches(
                content[body_start : inner_end - 1], compiled.pattern
            ):
                continue
            end = inner_end
        match = _FILE_UPLOAD_VALIDATED_SPAN_RE.match(content, start, end)
        if match is None:
            raise RuntimeError("the validated file upload span did not match")
        matches.append(match)
        last_end = end
    return matches


def _file_upload_double_extension_scan_matches(
    content: str, compiled: re.Pattern
) -> list[re.Match]:
    return list(
        bounded_finditer(
            content, compiled, _FILE_UPLOAD_DOUBLE_EXT_PREFIX_RE, _FILE_UPLOAD_QUOTE_RE
        )
    )
