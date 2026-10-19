import re
from typing import Any

_DEFAULT_MAX_SCAN_LENGTH = 10000
_DEFAULT_COMPILER_TIMEOUT = 2.0
_DEFAULT_MAX_BODY_INSPECT_BYTES = 262144


def _regex_anomaly(regex_threats: list[dict[str, Any]]) -> float:
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


def _supports_enhanced_config(config: Any) -> bool:
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


ALL_DETECTION_CATEGORIES: frozenset[str] = frozenset(
    {
        "xss",
        "sqli",
        "dir_traversal",
        "path_traversal",
        "cmd_injection",
        "file_inclusion",
        "ldap",
        "xml",
        "ssrf",
        "nosql",
        "file_upload",
        "template",
        "http_split",
        "sensitive_file",
        "cms_probing",
        "recon",
        "proto_pollution",
        "code_injection",
        "deserialization",
    }
)

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
_PATH_ONLY_SUFFIX_RE = rf"(?:{_PATH_ONLY_SEP_RE}{_PATH_ONLY_CHAR_RE}*)*(?:\?\S*)?\s*\Z"


def _path_only_pattern(required: str, trailing: str = "") -> str:
    return (
        rf"\A{_PATH_ONLY_SEP_RE}?"
        rf"(?:(?!{required}(?:{_PATH_ONLY_SEP_RE}|\Z))"
        rf"{_PATH_ONLY_CHAR_RE}+{_PATH_ONLY_SEP_RE})*"
        rf"{required}{trailing}{_PATH_ONLY_SUFFIX_RE}"
    )


def _root_path_pattern(required: str, trailing: str = "") -> str:
    return rf"\A{_PATH_ONLY_SEP_RE}?{required}{trailing}{_PATH_ONLY_SUFFIX_RE}"


def _root_extension_pattern(required: str) -> str:
    return (
        rf"\A{_PATH_ONLY_SEP_RE}?{_PATH_ONLY_CHAR_RE}*{required}{_PATH_ONLY_SUFFIX_RE}"
    )


def _path_only_extension_pattern(required: str) -> str:
    return (
        rf"\A{_PATH_ONLY_SEP_RE}?"
        rf"(?:{_PATH_ONLY_CHAR_RE}+{_PATH_ONLY_SEP_RE})*"
        rf"{_PATH_ONLY_CHAR_RE}*{required}{_PATH_ONLY_SUFFIX_RE}"
    )


_SENSITIVE_SOURCE_EXTENSION_PATH_RE = _root_extension_pattern(
    r"\.(?:ts|tsx|jsx|py|rb|java|go|rs|php|pl|sh|sql)"
)

_RECON_EXTENSION_PATH_RE = _root_extension_pattern(
    r"\.(?:asp|aspx|jsp|jsa|jhtml|shtml|cfm|cgi|do|action|lua|inc|woa|nsf|esp)"
)


def _nested_path_pattern(required: str) -> str:
    return (
        rf"\A{_PATH_ONLY_SEP_RE}"
        rf"(?:(?!{required}(?:{_PATH_ONLY_SEP_RE}|\Z))"
        rf"{_PATH_ONLY_CHAR_RE}+{_PATH_ONLY_SEP_RE})*"
        rf"{required}{_PATH_ONLY_SUFFIX_RE}"
    )


_ATTACK_REPORT_LEXICON_RE = (
    r"\b(?:scan(?:ner|ning|ned|s)?|attack(?:er|ers|ed|s)?|attempt(?:ed|s)?"
    r"|exploit(?:ation|ed|s|ing|kit)?|prob(?:e|ed|es|ing)|malicious|intrusion(?:s)?"
    r"|botnet(?:s)?|honeypot(?:s)?|brute[- ]force|credential[- ]stuffing"
    r"|threat feed|vulnerabilit(?:y|ies)|hostile|recon(?:naissance)?"
    r"|spoofed referer|bad actor(?:s)?|WAF|IDS|SOC|pentest(?:ing)?|blocked"
    r"|flagged|triggered|denied|enumerat(?:e|ed|ing)|suspicious)\b"
)


def _embedded_prose_pattern(required: str, trailing_max: int = 3) -> str:
    trailing = rf"(?:{_PATH_ONLY_SEP_RE}{_PATH_ONLY_CHAR_RE}{{1,64}})?" * trailing_max
    return (
        rf"\A(?=(?:(?!\n).)*{_ATTACK_REPORT_LEXICON_RE})"
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
_LDAP_BREAKOUT_WILDCARD_CLAUSE_END_RE = re.compile(r"=[^()]+\*\s*\Z")
_LDAP_BREAKOUT_ATTACK_TOKEN_RE = re.compile(r"\*|\(\s*[&|!]|\x00|\(\s*\(|~=|>=|<=")
_LDAP_FILTER_EXPRESSION_STRUCTURE_RE = re.compile(r"[()\"'\n]")

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
_LDAP_PAREN_CONJUNCTION_FOLLOWUP_SYMBOL_RE = re.compile(r"\A\s*(?:[!(]|\*)")
_LDAP_PAREN_CONJUNCTION_FOLLOWUP_ATTR_RE = re.compile(
    rf"\A\s*{_LDAP_ATTR_EXTENSIBLE_MATCH_RE}"
)

_LDAP_WILDCARD_EQUALS_RE = (
    rf"\*\s*\)+\s*(?:[|&!]\s*)?\(+\s*(?:[&|!]|{_LDAP_ATTR_EXTENSIBLE_MATCH_RE})"
)
_LDAP_PAREN_BREAKOUT_RE = rf"\)\s*\(\s*(?:[&|!]|{_LDAP_ATTR_DESC_RE}:?[=~<>])"

_SINGLE_LINE_PREFIX_RE = r"\A(?:(?!\n).)*"
_SINGLE_LINE_SUFFIX_RE = r"(?:[&#;,\"'<>]|\s*\Z)"

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

_LDAP_NULL_BYTE_ATTR_COMPILED_RE = re.compile(_LDAP_NULL_BYTE_ATTR_RE, re.IGNORECASE)
_LDAP_NULL_BYTE_DECODED_ATTR_COMPILED_RE = re.compile(
    _LDAP_NULL_BYTE_DECODED_ATTR_RE, re.IGNORECASE
)
_LDAP_NULL_BYTE_TAIL_RE = re.compile(r"\*\)+(?:%00|\\u0000|\\x00|\\0|\x00)")
_LDAP_NULL_BYTE_DECODED_TAIL_RE = re.compile(r"\*\)+\x00")
_LDAP_NULL_BYTE_VALUE_CHAR_RE = re.compile(r"[\d\w\s]")
_LDAP_NULL_BYTE_ATTR_CONTINUATION_CHAR_RE = re.compile(r"[\w-]")
_LDAP_NULL_BYTE_ATTR_LEAD_CHAR_RE = re.compile(r"[a-zA-Z]")
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
_SQLI_COMMENT_TERMINATOR_RE = r"'\s*(?:[\);]+\s*)?--|'[\);]*#(?:\n|\Z)"
_SQLI_WAITFOR_RE = (
    r"(?i)\bWAITFOR\s+(?:DELAY|TIME)\s+'\d{1,2}:\d{1,2}:\d{1,2}(?:\.\d+)?'"
)
_PATH_TRAVERSAL_ENCODED_DOT_RE = (
    r"(?:%2e%2e|%252e%252e|%uff0e%uff0e|%c0%ae%c0%ae|%e0%40%ae|%c0%ae"
    r"%e0%80%ae|%25c0%25ae)/"
)
_PATH_TRAVERSAL_SEMICOLON_SEP_RE = r"\.\.;[^/\\]*[/\\]"
_PATH_TRAVERSAL_DECODED_SHAPE_RE = re.compile(r"\.\.[\\/]")
_CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE = (
    r"\n[^\S\r\n]*(?:[^=\s;|&]+=[^\s;|&]+\s+)*(?:/?(?:[\w.-]+/)*env\s+)?/?(?:[\w.-]+/)*"
    r"(?:bash|sh|ksh|csh|tsch|zsh|ash)\s+-c\b"
)
_CMD_INJECTION_SHELL_DASH_FLAG_RE = (
    r"(?:\A|[;|&])\s*/?(?:[\w.-]+/)*(?:env\s+/?(?:[\w.-]+/)*)?"
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
