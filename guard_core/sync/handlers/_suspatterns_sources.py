import re
from collections.abc import Iterable, Mapping
from typing import TYPE_CHECKING, TypeGuard

from guard_core._detection_constants import (
    _DEFAULT_MAX_BODY_INSPECT_BYTES as _DEFAULT_MAX_BODY_INSPECT_BYTES,
)
from guard_core._detection_constants import (
    _DEFAULT_MAX_FILE_INSPECT_BYTES as _DEFAULT_MAX_FILE_INSPECT_BYTES,
)
from guard_core._detection_constants import (
    ALL_DETECTION_CATEGORIES as ALL_DETECTION_CATEGORIES,
)
from guard_core._lazy_patterns import LazyPatterns, module_attribute_lookup

if TYPE_CHECKING:
    from guard_core.models import SyncSecurityConfig

_DEFAULT_MAX_SCAN_LENGTH = 10000
_DEFAULT_COMPILER_TIMEOUT = 2.0


def _scan_window_bytes(config: "SyncSecurityConfig | None") -> int:
    return max(
        getattr(
            config, "detection_max_body_inspect_bytes", _DEFAULT_MAX_BODY_INSPECT_BYTES
        ),
        getattr(
            config, "detection_max_file_inspect_bytes", _DEFAULT_MAX_FILE_INSPECT_BYTES
        ),
    )


def _regex_anomaly(regex_threats: Iterable[Mapping[str, float]]) -> float:
    return float(sum(t.get("weight", 1.0) for t in regex_threats))


_ENHANCED_CONFIG_REQUIRED_ATTRS = (
    "detection_compiler_timeout",
    "detection_max_tracked_patterns",
    "detection_max_content_length",
    "detection_preserve_attack_patterns",
    "detection_anomaly_threshold",
    "detection_slow_pattern_threshold",
    "detection_monitor_history_size",
    "detection_anomaly_emission_cooldown",
    "detection_min_samples_for_anomaly",
    "detection_semantic_threshold",
    "detection_threat_score_threshold",
)


def _supports_enhanced_config(config: object) -> TypeGuard["SyncSecurityConfig"]:
    return config is not None and all(
        hasattr(config, attr) for attr in _ENHANCED_CONFIG_REQUIRED_ATTRS
    )


_CTX_XSS = frozenset({"query_param", "header", "request_body", "url_path", "unknown"})
_CTX_SQLI = frozenset({"query_param", "header", "request_body", "url_path", "unknown"})
_CTX_SQLI_NARROW = frozenset({"query_param", "request_body", "unknown"})
_CTX_DIR_TRAVERSAL = frozenset(
    {"url_path", "query_param", "header", "request_body", "unknown"}
)
_CTX_CMD_INJECTION = frozenset({"query_param", "header", "request_body", "unknown"})
_CTX_FILE_INCLUSION = frozenset(
    {"url_path", "query_param", "header", "request_body", "unknown"}
)
_CTX_LDAP = frozenset({"query_param", "header", "url_path", "request_body", "unknown"})
_CTX_XML = frozenset({"header", "request_body", "unknown", "query_param", "url_path"})
_CTX_SSRF = frozenset({"query_param", "header", "request_body", "url_path", "unknown"})
_CTX_NOSQL = frozenset({"query_param", "header", "url_path", "request_body", "unknown"})
_CTX_FILE_UPLOAD = frozenset({"header", "query_param", "request_body", "unknown"})
_CTX_PATH_TRAVERSAL = frozenset(
    {"url_path", "query_param", "header", "request_body", "unknown"}
)
_CTX_TEMPLATE = frozenset(
    {"query_param", "header", "request_body", "url_path", "unknown"}
)
_CTX_HTTP_SPLIT = frozenset(
    {"header", "query_param", "url_path", "request_body", "unknown"}
)
_CTX_SENSITIVE_FILE = frozenset({"url_path", "query_param", "request_body", "unknown"})
_EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX = ":embedded_json"


def _source_extension_path_is_probe(context: str) -> bool:
    return not context.endswith(_EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX)


_CTX_CMS_PROBING = frozenset({"url_path", "query_param", "request_body", "unknown"})
_CTX_RECON = frozenset({"url_path", "query_param", "request_body", "unknown"})
_RECON_BARE_PATH_CONTEXTS = frozenset({"url_path", "unknown"})


def _recon_path_value_is_probe(match: re.Match, context: str) -> bool:
    return context.split(":", 1)[0] in _RECON_BARE_PATH_CONTEXTS or (
        match.group().startswith(("/", "\\"))
    )


_CTX_PROTO_POLLUTION = frozenset(
    {"query_param", "header", "url_path", "request_body", "unknown"}
)
_CTX_CODE_INJECTION = frozenset(
    {"query_param", "header", "url_path", "request_body", "unknown"}
)
_CTX_DESERIALIZATION = frozenset(
    {"query_param", "header", "url_path", "request_body", "unknown"}
)
_CTX_ALL = frozenset({"query_param", "header", "url_path", "request_body", "unknown"})


CATEGORY_CONTEXT_MAP: dict[str, frozenset[str]] = {
    "xss": _CTX_XSS,
    "sqli": _CTX_SQLI,
    "dir_traversal": _CTX_DIR_TRAVERSAL,
    "path_traversal": _CTX_PATH_TRAVERSAL,
    "cmd_injection": _CTX_CMD_INJECTION,
    "file_inclusion": _CTX_FILE_INCLUSION,
    "ldap": _CTX_LDAP,
    "xml": _CTX_XML,
    "ssrf": _CTX_SSRF,
    "nosql": _CTX_NOSQL,
    "file_upload": _CTX_FILE_UPLOAD,
    "template": _CTX_TEMPLATE,
    "http_split": _CTX_HTTP_SPLIT,
    "sensitive_file": _CTX_SENSITIVE_FILE,
    "cms_probing": _CTX_CMS_PROBING,
    "recon": _CTX_RECON,
    "proto_pollution": _CTX_PROTO_POLLUTION,
    "code_injection": _CTX_CODE_INJECTION,
    "deserialization": _CTX_DESERIALIZATION,
}

_PROSE_DETERMINER_RE = (
    r"(?:the|a|an|my|our|your|his|her|its|their|this|that|these|those|which|what"
    r"|any|some|each|every|many|more|most)"
)
_SELECT_FROM_RE = (
    r"(?i)\bSELECT\b(?:(?!\bSELECT\b)[\w\s,\*().])*?\bFROM\b"
    rf"(?!\s+{_PROSE_DETERMINER_RE}\b)"
)
_SELECT_STAR_RE = r"(?i)SELECT\s+\*"
_WHERE_CLAUSE_RE = r'(?i)\bWHERE\s+[\w."]+\s*(?:=|<|>|<=|>=|LIKE|IN)\b'
_SQLI_TAUTOLOGY_RE = (
    r"(?i)\b(?:OR|AND)\s*(\d+|'[^']*'|\"[^\"]*\"|[@:$][A-Za-z_]\w*)\s*=\s*\1\b"
    r"(?!\s+(?:is|are|was|means|equals|always|holds|being)\b)"
)

_PATH_ONLY_CHAR_RE = r"[\w.\-~%]"
_PATH_ONLY_SEP_RE = r"[/\\]"
_PATH_ONLY_PREFIX_RE = (
    rf"\A{_PATH_ONLY_SEP_RE}?(?:{_PATH_ONLY_CHAR_RE}+{_PATH_ONLY_SEP_RE})*"
)
# Zero or more "/segment" groups, written as one separator then a flat run of separator
# and name characters (the same language), so a failing tail backtracks one character
# at a time instead of one group and one character at a time.
_PATH_ONLY_REST_RE = rf"(?:{_PATH_ONLY_SEP_RE}[/\\\w.\-~%]*)?"
_PATH_ONLY_SUFFIX_RE = rf"{_PATH_ONLY_REST_RE}(?:\?\S*)?\s*\Z"


def _path_only_pattern(
    required: str,
    trailing: str = "",
    suffix: str = _PATH_ONLY_SUFFIX_RE,
    first_characters: str = "",
) -> str:
    # first_characters lists every character the required name can start with
    # (both cases): a segment that starts with anything else skips the name
    # alternation, which is what keeps a long run of ordinary segments cheap.
    gated = rf"(?=[{first_characters}]){required}" if first_characters else required
    return (
        rf"\A{_PATH_ONLY_SEP_RE}?"
        rf"(?:(?!{gated}(?:{_PATH_ONLY_SEP_RE}|\Z))"
        rf"{_PATH_ONLY_CHAR_RE}+{_PATH_ONLY_SEP_RE})*"
        rf"{gated}{trailing}{suffix}"
    )


def _root_path_pattern(required: str, trailing: str = "") -> str:
    return rf"\A{_PATH_ONLY_SEP_RE}?{required}{trailing}{_PATH_ONLY_SUFFIX_RE}"


_PATH_ONLY_SEGMENT_END_RE = r"(?![^/\\?\s])"


def _path_only_extension_pattern(required: str) -> str:
    # The row ends the head at the last segment that ends in the extension and takes
    # the rest as-is; path_only_extension_tail_is_valid judges that rest once.
    return (
        rf"\A{_PATH_ONLY_SEP_RE}?(?P<head>"
        rf"(?:{_PATH_ONLY_CHAR_RE}+{_PATH_ONLY_SEP_RE})*"
        rf"{_PATH_ONLY_CHAR_RE}*{required}{_PATH_ONLY_SEGMENT_END_RE})[\s\S]*"
    )


def path_only_extension_tail_is_valid(match: re.Match[str]) -> bool:
    return (
        _PATTERNS["_PATH_ONLY_TAIL_RE"].fullmatch(match.string, match.end("head"))
        is not None
    )


# Expansion over v4.4.0 (D-75 step 4): alternate server-side extensions, and the
# suffix tricks that make a server run a file under another name (";params",
# "%00", trailing dots, "::$DATA", a trailing image extension). They sit
# behind the same route gate as the v4.4.0 extensions.
# The ";" and "%00" tails read "anything but a separator, a query mark or a space" as a
# lookahead per character: the same language as [^/\\?\s]*, but the row then holds a
# single broad unbounded quantifier (the one after "?") and the ReDoS validator times
# the row instead of flagging two adjacent ones.
# The control characters the preprocessor deletes (tab, LF and CR stay), as the decoded
# character; "%00", "\\u0000" and "\\x00" are the literal texts of a NUL.
DELETED_CONTROL_CHAR_CLASS = r"[\x00-\x08\x0b\x0c\x0e-\x1f]"
NUL_TAIL_MARKER = rf"(?:%00|\\u0000|\\x00|{DELETED_CONTROL_CHAR_CLASS})"
_EXTENSION_TRICK_SUFFIX = (
    r"(?:;(?:(?![/\\?])\S)*|\.+|::\$(?:DATA|INDEX_ALLOCATION)"
    rf"|{NUL_TAIL_MARKER}(?:(?![/\\?])\S)*|\.(?:jpe?g|png|gif|ico|bmp))?"
)
_NAMED_PATH_SUFFIX_RE = (
    rf"{_PATH_ONLY_REST_RE}{_EXTENSION_TRICK_SUFFIX}"
    r"(?:\?\S*)?\s*\Z"
)
_SENSITIVE_SOURCE_BARE_EXTENSIONS = (
    r"\.(?:ts|tsx|jsx|py|rb|java|go|rs|p(?:hp(?:[3-8]|s)?|ht(?:ml)?|har|l)|s(?:h|ql))"
)
_SENSITIVE_SOURCE_EXTENSIONS = (
    _SENSITIVE_SOURCE_BARE_EXTENSIONS + _EXTENSION_TRICK_SUFFIX
)
_RECON_EXTENSIONS = (
    r"\.(?:asp|aspx|j(?:s[pa]|html)|shtml|c(?:fm|gi|er)|do|lua|inc|woa|nsf|esp"
    r"|a(?:sa|shx|smx|scx|ction))" + _EXTENSION_TRICK_SUFFIX
)

_SENSITIVE_SOURCE_EXTENSION_PATH_RE = _path_only_extension_pattern(
    _SENSITIVE_SOURCE_EXTENSIONS
)

_RECON_EXTENSION_PATH_RE = _path_only_extension_pattern(_RECON_EXTENSIONS)

_MAP_FILE_PATH_RE = _path_only_pattern(rf"{_PATH_ONLY_CHAR_RE}*\.map")

_VERSION_ROOT_PATH_RE = (
    rf"\A{_PATH_ONLY_SEP_RE}?version{_PATH_ONLY_SEP_RE}?(?:\?\S*)?\s*\Z"
)

_SYSTEM_LOG_PATH_RE = (
    rf"\A{_PATH_ONLY_SEP_RE}?system{_PATH_ONLY_SEP_RE}logs?"
    rf"{_PATH_ONLY_SEP_RE}?(?:\?\S*)?\s*\Z"
)


def _nested_path_pattern(required: str) -> str:
    return (
        rf"\A{_PATH_ONLY_SEP_RE}"
        rf"(?:(?!{required}(?:{_PATH_ONLY_SEP_RE}|\Z))"
        rf"{_PATH_ONLY_CHAR_RE}+{_PATH_ONLY_SEP_RE})*"
        rf"{required}{_PATH_ONLY_SUFFIX_RE}"
    )


_ATTACK_REPORT_LEXICON_RE = (
    r"\b(?=[sSaAeEpPmMiIbBhHcCtTvVrRwWfFdD])"
    r"(?:scan(?:ner|ning|ned|s)?|attack(?:er|ers|ed|s)?|attempt(?:ed|s)?"
    r"|exploit(?:ation|ed|s|ing|kit)?|prob(?:e|ed|es|ing)|malicious|intrusion(?:s)?"
    r"|botnet(?:s)?|honeypot(?:s)?|brute[- ]force|credential[- ]stuffing"
    r"|threat feed|vulnerabilit(?:y|ies)|hostile|recon(?:naissance)?"
    r"|spoofed referer|bad actor(?:s)?|WAF|IDS|SOC|pentest(?:ing)?|blocked"
    r"|flagged|triggered|denied|enumerat(?:e|ed|ing)|suspicious)\b"
)


def _embedded_prose_pattern(required: str, trailing_max: int = 3) -> str:
    trailing = rf"(?:{_PATH_ONLY_SEP_RE}{_PATH_ONLY_CHAR_RE}{{1,64}})?" * trailing_max
    return (
        rf"\A(?=[^\n]*{_ATTACK_REPORT_LEXICON_RE})"
        rf"{_SINGLE_LINE_PREFIX_RE}{_PATH_ONLY_SEP_RE}"
        rf"(?:{required}){trailing}\b"
    )


_TOP_LEVEL_PATH_PREFIX_RE = rf"\A{_PATH_ONLY_SEP_RE}?"
_TERMINAL_PATH_SUFFIX_RE = rf"(?:{_PATH_ONLY_SEP_RE})?(?:\?\S*)?\s*\Z"

_LDAP_ATTR_DESC_RE = (
    r"(?::)?(?:[a-zA-Z][\w.-]*|\d+(?:\.\d+)*)"
    r"(?:;[\w.-]+)*(?::[\w.-]+)*\s*"
)
_LDAP_ATTR_EXTENSIBLE_MATCH_RE = _LDAP_ATTR_DESC_RE + r":?="

_LDAP_WILDCARD_CHAIN_RE = rf"\*\)[|&]?\(+\s*{_LDAP_ATTR_EXTENSIBLE_MATCH_RE}"
_LDAP_BREAKOUT_BACKWARD_BOUNDARY_CHARS = frozenset("\"'\n&")
_LDAP_BREAKOUT_FORWARD_BOUNDARY_CHARS = frozenset("\"'\n")
_LDAP_BREAKOUT_LOCAL_SCAN_CHARS = 40

_PROTO_POLLUTION_PROTOTYPE_ASSIGN_RE = r"Object\.prototype\.[A-Za-z_$][\w$]*\s*=(?!=)"
_PROTO_POLLUTION_SET_PROTOTYPE_OF_RE = r"\b(?:Object|Reflect)\.setPrototypeOf\s*\("

_XML_XXE_PUBLIC_EXTERNAL_DTD_RE = (
    r"<!DOCTYPE[^>\[]+PUBLIC[^>\[]+[\"']https?://"
    r"(?!(?:www\.)?w3\.org/)[^\"'>]+[\"'][^>\[]*>"
)

_XSS_JS_SCHEME_CTRL_CHAR_RE = (
    r"j[\t\r\n]*a[\t\r\n]*v[\t\r\n]*a[\t\r\n]*s[\t\r\n]*c[\t\r\n]*r[\t\r\n]*i"
    r"[\t\r\n]*p[\t\r\n]*t[\t\r\n]*:\s*[^\s]+"
)

_FILE_INCLUSION_JSON_VALUE_RE = (
    r"[\"'](?:template|include|tpl|module|layout)[\"']\s*:\s*"
    r"[\"'](?:https?|ftp)://[^\s'\"<>]+/[^\s'\"<>/]*\.(?:phtml|php[3-5]?|"
    r"phar|jsp|aspx?|cgi|pl|py|sh|txt|inc)(?![a-zA-Z0-9])[\"']"
)

_SSRF_BARE_METADATA_ALIAS_RE = r"://(?:metadata|instance-data)(?::\d+)?(?:/|\s|$)"

_CMD_INJECTION_NODE_CHILD_PROCESS_RE = (
    r"(?:require\(\s*[\"']child_process[\"']\s*\)|child_process)\s*\.\s*"
    r"(?:execSync|spawnSync|spawn|fork)\s*\("
)
_CMD_INJECTION_PHP_ASSERT_VARIABLE_RE = r"\bassert\s*\(\s*\$"
_CMD_INJECTION_PYTHON_EXEC_FAMILY_RE = r"\bos\.exec(?:l|le|lp|lpe|v|ve|vp|vpe)\s*\("

_JS_DYNAMIC_EVAL_FUNCTION_CTOR_RE = r"\b(?:new\s+)?Function\s*\(\s*[\"']"
_JS_DYNAMIC_EVAL_BRACKET_RE = r"\[\s*[\"']eval[\"']\s*\]\s*\(\s*[\"']"
_JS_DYNAMIC_EVAL_CTOR_GADGET_RE = (
    r"(?:\.\s*constructor|\[\s*[\"']constructor[\"']\s*\])"
    r"\s*(?:\.\s*constructor|\[\s*[\"']constructor[\"']\s*\])"
    r"\s*\(\s*[\"']"
)
_JS_DYNAMIC_EVAL_TIMER_STRING_ARG_RE = r"\b(?:setTimeout|setInterval)\s*\(\s*[\"']"


_LDAP_PAREN_CONJUNCTION_RE = r"\(\s*[&|]\s*"

_LDAP_WILDCARD_EQUALS_RE = (
    rf"\*\s*\)+\s*(?:[|&!]\s*)?\(+\s*(?:[&|!]|{_LDAP_ATTR_EXTENSIBLE_MATCH_RE})"
)
_LDAP_PAREN_BREAKOUT_RE = rf"\)\s*\(\s*(?:[&|!]|{_LDAP_ATTR_DESC_RE}:?[=~<>])"

_SINGLE_LINE_PREFIX_RE = r"\A(?:(?!\n).)*"
_SINGLE_LINE_SUFFIX_RE = rf"(?:[&#;,\"'<>]|{DELETED_CONTROL_CHAR_CLASS}|\s*\Z)"

_FILE_INCLUSION_HOST_LABEL_RE = r"[0-9a-zA-Z](?:[-\w]*[0-9a-zA-Z])?"
_FILE_INCLUSION_BARE_HOST_RE = (
    rf"(?:(?<!:)\/\/{_FILE_INCLUSION_HOST_LABEL_RE}"
    rf"(?:\.{_FILE_INCLUSION_HOST_LABEL_RE})+(:[0-9]+)?(?:\/?)(?:"
    r"[a-zA-Z0-9\-\.\?,'/\\\+&amp;%\$#_]*)?)"
)

_LDAP_NULL_BYTE_ATTR_RE = (
    r"[a-zA-Z][\w-]*\s*=[\d\w\s]*\*\)+(?:%00|\\u0000|\\x00|\\0|\x00)"
)
_LDAP_NULL_BYTE_BARE_RE = r"\*\)\)+(?:%00|\\u0000|\\x00|\\0|\x00)"
_LDAP_NULL_BYTE_DECODED_ATTR_RE = r"[a-zA-Z][\w-]*\s*=[\d\w\s]*\*\)+\x00"
_LDAP_NULL_BYTE_DECODED_BARE_RE = r"\*\)\)+\x00"

_PATTERNS = LazyPatterns(
    {
        "_PATH_ONLY_TAIL_RE": (
            rf"(?:{_PATH_ONLY_SEP_RE}[\w.\-~%/\\]*)?(?:\?\S*)?\s*\Z",
            0,
        ),
        "_PLAIN_SOURCE_OR_MAP_PATH_END_RE": (
            rf"(?:{_SENSITIVE_SOURCE_BARE_EXTENSIONS}|\.map)\s*\Z",
            0,
        ),
        "_LDAP_BREAKOUT_WILDCARD_CLAUSE_END_RE": (r"=[^()]+\*\s*\Z", 0),
        "_LDAP_BREAKOUT_ATTACK_TOKEN_RE": (r"\*|\(\s*[&|!]|\x00|\(\s*\(|~=|>=|<=", 0),
        "_LDAP_FILTER_EXPRESSION_STRUCTURE_RE": (r"[()\"'\n]", 0),
        "_LDAP_PAREN_CONJUNCTION_FOLLOWUP_SYMBOL_RE": (r"\A\s*(?:[!(]|\*)", 0),
        "_LDAP_PAREN_CONJUNCTION_FOLLOWUP_ATTR_RE": (
            rf"\A\s*{_LDAP_ATTR_EXTENSIBLE_MATCH_RE}",
            0,
        ),
        "_LDAP_NULL_BYTE_ATTR_COMPILED_RE": (_LDAP_NULL_BYTE_ATTR_RE, re.IGNORECASE),
        "_LDAP_NULL_BYTE_DECODED_ATTR_COMPILED_RE": (
            _LDAP_NULL_BYTE_DECODED_ATTR_RE,
            re.IGNORECASE,
        ),
        "_LDAP_NULL_BYTE_TAIL_RE": (r"\*\)+(?:%00|\\u0000|\\x00|\\0|\x00)", 0),
        "_LDAP_NULL_BYTE_DECODED_TAIL_RE": (r"\*\)+\x00", 0),
        "_LDAP_NULL_BYTE_VALUE_CHAR_RE": (r"[\d\w\s]", 0),
        "_LDAP_NULL_BYTE_ATTR_CONTINUATION_CHAR_RE": (r"[\w-]", 0),
        "_LDAP_NULL_BYTE_ATTR_LEAD_CHAR_RE": (r"[a-zA-Z]", 0),
    }
)
__getattr__ = module_attribute_lookup(_PATTERNS)


_HTTP_SPLIT_CRLF_RE = r"[\r\n][^\S\r\n]*(?:HTTP\/[0-9.]+|Location:|Set-Cookie:)"
_SQLI_ORDER_BY_TERMINATOR_RE = (
    r"(?i)\bORDER\s+BY\s+\d+\s*(?:--|#|;|\)|,|/\*|\Z)"
    r"|(?<=[=?&])ORDER\s+BY\s+\d+\s*\n"
)
_SQLI_ORDER_BY_STRONG_RE = (
    r"(?i)(?:['\")\d]|/\*)\s{0,3}\bORDER\s+BY\s+\d+"
    r"|\bORDER\s+BY\s+\d+\s*(?:--|#|/\*)"
)
_SQLI_EXEC_STRONG_RE = r"(?i)(?:\A|[;'\"])\s*EXEC(?:UTE)?\s+(?:xp_\w+|sp_\w+)"
_SQLI_COMMENT_TERMINATOR_RE = (
    r"'\s*(?:[\);]+\s*)?(?:--|/\*(?![^*]+\*/))"
    r"|'[\);]*#(?:\n|\Z)|'[\);]*[^\S\n]+#[^\S\n]*\Z"
)
_SQLI_INLINE_COMMENT_RE = r"/\*[^*]{0,40}\*/"
_SQLI_GAP_RE = rf"(?:\s|{_SQLI_INLINE_COMMENT_RE})"
_SQLI_OPEN_GAP_RE = rf"(?:\s|\(|{_SQLI_INLINE_COMMENT_RE})"
_SQLI_QUOTED_TAUTOLOGY_RE = (
    r"(?i)(?:OR|AND)\s+(?:'[\w\d]*'='[\w\d]*'?|"
    r"[@:$][A-Za-z_]\w*\s*=\s*[@:$][A-Za-z_]\w*)"
    rf"|\b(?:OR|AND){_SQLI_OPEN_GAP_RE}*(?:'\w*'|\"\w*\")"
    rf"{_SQLI_GAP_RE}*(?:=|!=|<>|LIKE){_SQLI_OPEN_GAP_RE}*(?:'\w*'?|\"\w*\"?)"
    rf"|['\")]{_SQLI_GAP_RE}*\b(?:OR|AND){_SQLI_GAP_RE}+TRUE\b"
    rf"(?:{_SQLI_GAP_RE}*(?:--|/\*(?![^*]+\*/))|[^\S\n]*#[^\S\n]*(?:\n|\Z))"
)
_SQLI_WAITFOR_RE = (
    r"(?i)\bWAITFOR\s+(?:DELAY|TIME)\s+'\d{1,2}:\d{1,2}:\d{1,2}(?:\.\d+)?'"
)
_PATH_TRAVERSAL_ENCODED_DOT_RE = (
    r"(?:%2e%2e|%252e%252e|%uff0e%uff0e|%c0%ae%c0%ae|%e0%40%ae|%c0%ae"
    r"%e0%80%ae|%25c0%25ae)/"
)
_PATH_TRAVERSAL_SEMICOLON_SEP_RE = r"\.\.;[^/\\]*[/\\]"
_PATH_TRAVERSAL_DECODED_SHAPE_RE = re.compile(r"\.\.[\\/]")


def _count_path_traversal_shapes(text: str) -> int:
    """How many matches ``_PATH_TRAVERSAL_DECODED_SHAPE_RE`` finds in ``text``.

    A match is ``..`` and a separator, so two matches never overlap and the count
    is the occurrences of ``../`` and of ``..\\``, with no list of matches.
    """
    return text.count("../") + text.count("..\\")


_CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE = (
    r"\n[^\S\r\n]*(?:[^=\s;|&]+=[^\s;|&]+\s+)*(?:/?(?:[\w.-]+/)*env\s+)?/?(?:[\w.-]+/)*"
    r"(?:bash|sh|ksh|csh|tsch|zsh|ash)\s+-c\b"
)
_CMD_INJECTION_SHELL_DASH_FLAG_RE = (
    r"(?:\A|[;|&])\s*(?=[/\w.\-])/?(?:[\w.-]+/)*(?:env\s+/?(?:[\w.-]+/)*)?"
    r"(?:bash|sh|ksh|csh|tsch|zsh|ash)\s+-[a-zA-Z]+"
    r"(?:\s+(?:'[^']*'|\"[^\"]*\"|[^\s;|&]+))?"
    r"(?=\s*(?:[;|&]|\Z))"
)
_DIR_TRAVERSAL_ETC_SENSITIVE_RE = (
    _SINGLE_LINE_PREFIX_RE
    + r"etc/(?:passwd|shadow|group|hosts|motd|issue|mysql/my\.cnf|ssh/ssh_config)"
    + _SINGLE_LINE_SUFFIX_RE
)
_DIR_TRAVERSAL_WINDOWS_INI_RE = (
    _SINGLE_LINE_PREFIX_RE
    + r"(?:boot\.ini|win\.ini|system\.ini|config\.sys)"
    + _SINGLE_LINE_SUFFIX_RE
)
_DIR_TRAVERSAL_PROC_ENVIRON_RE = (
    _SINGLE_LINE_PREFIX_RE + r"proc/self/environ" + _SINGLE_LINE_SUFFIX_RE
)
_DIR_TRAVERSAL_VAR_LOG_RE = (
    _SINGLE_LINE_PREFIX_RE + r"var/log/[^\s/]+" + _SINGLE_LINE_SUFFIX_RE
)
_SSTI_HASH_BRACE_SHAPE_RE = (
    r"#\{(?![^\}]*\d{4}-\d{1,2}-\d{1,2}(?!\d))"
    r"(?=[^\}]*(?:@[\w.]+@|\b\w+\s*\("
    r"|['\"]?\d+['\"]?\s*[*/%+\-]\s*['\"]?\d+['\"]?))"
    r"[^\}]*\}"
)


_DESERIALIZATION_JAVA_B64_RE = r"(?<![A-Za-z0-9+/])(?-i:rO0AB)"
_DESERIALIZATION_DOTNET_B64_RE = r"(?<![A-Za-z0-9+/])(?-i:AAEAAAD)"
_DESERIALIZATION_PICKLE_B64_RE = r"(?<![A-Za-z0-9+/])(?-i:gA[SW]V)"
_DESERIALIZATION_RUBY_B64_RE = r"(?<![A-Za-z0-9+/])(?-i:BAh[Jv7bV])"
_DESERIALIZATION_PICKLE_OS_GLOBAL_RE = r"cos\n"
_PICKLE_IDENT_RE = r"[A-Za-z_][A-Za-z0-9_]{0,100}"
_PICKLE_DOTTED_MODULE_RE = rf"{_PICKLE_IDENT_RE}(?:\.{_PICKLE_IDENT_RE}){{0,20}}"
_DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE = (
    rf"(c{_PICKLE_DOTTED_MODULE_RE}\n{_PICKLE_IDENT_RE}\n)[^ \t]{{0,100}}?[Rb]"
)
_PICKLE_OPCODE_WORK_BUDGET_BYTES = 4096
