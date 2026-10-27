import re

from guard_core.detection_engine.scan_window import bounded_finditer

_FILE_UPLOAD_SERVER_CONFIG_EXTENSIONS = frozenset(
    {"htaccess", "htpasswd", "config", "inc"}
)
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
    + r")[\"']"
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
    + r"[\"'][^\"']*\.(?:"
    + _FILE_UPLOAD_DANGEROUS_EXT_ALTERNATION
    + r")[\"']"
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
    r"\.(?:" + _FILE_UPLOAD_DANGEROUS_EXT_ALTERNATION + r")\Z", re.IGNORECASE
)
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


def _file_upload_kind_matches(body: str, source: str) -> bool:
    if source == _FILE_UPLOAD_DANGEROUS_EXTENSION_RE:
        return _FILE_UPLOAD_DANGEROUS_TERMINAL_EXTENSION_RE.search(body) is not None
    if source == _FILE_UPLOAD_DOUBLE_EXTENSION_RE:
        return _file_upload_is_double_extension(body)
    if source == _FILE_UPLOAD_TRUNCATION_RE:
        return _file_upload_is_truncation(body, decoded=False)
    if source == _FILE_UPLOAD_DECODED_TRUNCATION_RE:
        return _file_upload_is_truncation(body, decoded=True)
    return False


def _file_upload_scan_matches(content: str, compiled: re.Pattern) -> list[re.Match]:
    matches = []
    last_end = 0
    for filename in _FILE_UPLOAD_FILENAME_TOKEN_RE.finditer(content):
        candidate = _file_upload_quoted_candidate(content, filename.start())
        if candidate is None:
            continue
        start, body_start, end = candidate
        if start < last_end or not _file_upload_kind_matches(
            content[body_start : end - 1], compiled.pattern
        ):
            continue
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
