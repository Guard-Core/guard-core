import re
from collections.abc import Callable

from guard_core.handlers._suspatterns_matchers import (
    _CMD_INJECTION_DOLLAR_SUBSTITUTION_RE,
    _FILE_UPLOAD_DANGEROUS_EXTENSION_RE,
    _FILE_UPLOAD_DECODED_TRUNCATION_RE,
    _FILE_UPLOAD_DOUBLE_EXTENSION_RE,
    _FILE_UPLOAD_TRUNCATION_RE,
    _SQLI_LOAD_FILE_RE,
    _TEMPLATE_ASP_KEYWORD_RE,
    _TEMPLATE_CURLY_CALL_RE,
    _TEMPLATE_CURLY_KEYWORD_RE,
    _TEMPLATE_DOLLAR_BRACE_CALL_RE,
    _TEMPLATE_PERCENT_KEYWORD_RE,
    _cmd_injection_dollar_scan_matches,
    _file_upload_scan_matches,
    _load_file_scan_matches,
    _template_asp_keyword_scan_matches,
    _template_curly_call_scan_matches,
    _template_curly_keyword_scan_matches,
    _template_dollar_brace_scan_matches,
    _template_hash_brace_scan_matches,
    _template_percent_keyword_scan_matches,
)
from guard_core.handlers._suspatterns_recall_rows import (
    _CMD_NEWLINE_COMMAND_DECODED_RE,
    _CMD_NEWLINE_COMMAND_RE,
    _HTTP_SPLIT_CRLF_DECODED_RE,
    _TEMPLATE_FREEMARKER_EXECUTE_RE,
    _TEMPLATE_OGNL_RE,
    _TEMPLATE_VELOCITY_SET_RE,
)
from guard_core.handlers._suspatterns_sources import (
    _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE,
    _DESERIALIZATION_DOTNET_B64_RE,
    _DESERIALIZATION_JAVA_B64_RE,
    _DESERIALIZATION_PICKLE_B64_RE,
    _DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE,
    _DESERIALIZATION_PICKLE_OS_GLOBAL_RE,
    _DESERIALIZATION_RUBY_B64_RE,
    _DIR_TRAVERSAL_ETC_SENSITIVE_RE,
    _DIR_TRAVERSAL_PROC_ENVIRON_RE,
    _DIR_TRAVERSAL_VAR_LOG_RE,
    _DIR_TRAVERSAL_WINDOWS_INI_RE,
    _HTTP_SPLIT_CRLF_RE,
    _LDAP_NULL_BYTE_ATTR_RE,
    _LDAP_NULL_BYTE_BARE_RE,
    _LDAP_NULL_BYTE_DECODED_ATTR_RE,
    _LDAP_NULL_BYTE_DECODED_BARE_RE,
    _PATH_TRAVERSAL_ENCODED_DOT_RE,
    _SQLI_COMMENT_TERMINATOR_RE,
    _SQLI_ORDER_BY_STRONG_RE,
    _SQLI_ORDER_BY_TERMINATOR_RE,
    _SSTI_HASH_BRACE_SHAPE_RE,
    _XSS_JS_SCHEME_CTRL_CHAR_RE,
)

_PATTERN_SCAN_WINDOW_MATCHERS: dict[
    str, Callable[[str, re.Pattern], list[re.Match]]
] = {
    _SQLI_LOAD_FILE_RE: _load_file_scan_matches,
    _CMD_INJECTION_DOLLAR_SUBSTITUTION_RE: _cmd_injection_dollar_scan_matches,
    _FILE_UPLOAD_DANGEROUS_EXTENSION_RE: _file_upload_scan_matches,
    _FILE_UPLOAD_DOUBLE_EXTENSION_RE: _file_upload_scan_matches,
    _FILE_UPLOAD_TRUNCATION_RE: _file_upload_scan_matches,
    _FILE_UPLOAD_DECODED_TRUNCATION_RE: _file_upload_scan_matches,
    _TEMPLATE_CURLY_KEYWORD_RE: _template_curly_keyword_scan_matches,
    _TEMPLATE_DOLLAR_BRACE_CALL_RE: _template_dollar_brace_scan_matches,
    _TEMPLATE_CURLY_CALL_RE: _template_curly_call_scan_matches,
    _TEMPLATE_PERCENT_KEYWORD_RE: _template_percent_keyword_scan_matches,
    _TEMPLATE_ASP_KEYWORD_RE: _template_asp_keyword_scan_matches,
    _SSTI_HASH_BRACE_SHAPE_RE: _template_hash_brace_scan_matches,
}


DETECTION_RAW_VIEW_PATTERN_SOURCES: frozenset[str] = frozenset(
    {
        _CMD_NEWLINE_COMMAND_RE,
        _TEMPLATE_FREEMARKER_EXECUTE_RE,
        _TEMPLATE_OGNL_RE,
        _TEMPLATE_VELOCITY_SET_RE,
        _LDAP_NULL_BYTE_ATTR_RE,
        _LDAP_NULL_BYTE_BARE_RE,
        _HTTP_SPLIT_CRLF_RE,
        _SQLI_ORDER_BY_TERMINATOR_RE,
        _SQLI_COMMENT_TERMINATOR_RE,
        _PATH_TRAVERSAL_ENCODED_DOT_RE,
        _SSTI_HASH_BRACE_SHAPE_RE,
        _DESERIALIZATION_JAVA_B64_RE,
        _DESERIALIZATION_DOTNET_B64_RE,
        _DESERIALIZATION_PICKLE_B64_RE,
        _DESERIALIZATION_RUBY_B64_RE,
        _DESERIALIZATION_PICKLE_OS_GLOBAL_RE,
        _DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE,
        _FILE_UPLOAD_TRUNCATION_RE,
        _FILE_UPLOAD_DOUBLE_EXTENSION_RE,
        _XSS_JS_SCHEME_CTRL_CHAR_RE,
    }
)

DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES: frozenset[str] = frozenset(
    {
        _CMD_NEWLINE_COMMAND_DECODED_RE,
        _HTTP_SPLIT_CRLF_DECODED_RE,
        _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE,
        _DIR_TRAVERSAL_ETC_SENSITIVE_RE,
        _DIR_TRAVERSAL_WINDOWS_INI_RE,
        _DIR_TRAVERSAL_PROC_ENVIRON_RE,
        _DIR_TRAVERSAL_VAR_LOG_RE,
        _FILE_UPLOAD_DECODED_TRUNCATION_RE,
        _LDAP_NULL_BYTE_DECODED_ATTR_RE,
        _LDAP_NULL_BYTE_DECODED_BARE_RE,
        _SQLI_ORDER_BY_STRONG_RE,
    }
)

_GLUED_BACKTICK_CANDIDATE_RE = r"(?<!`)`(?:[A-Za-z0-9_./~]|\$[({])(?:[^`\\\n]|\\.)*`"
_GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE = (
    r"\$\((?:[^()\\\n]|\\.)*\)|\$\{(?:[^{}\\\n]|\\.)*\}"
)
_GLUED_BACKTICK_ASCII_WORD_RE = re.compile(r"[A-Za-z0-9_]")

_STRONG_SQL_KEYWORD_GLUED_PREFIX_RE = re.compile(
    r"(?i)\b(?:SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|JOIN|VALUES|ORDER\s+BY|"
    r"GROUP\s+BY)\Z"
)
_STRONG_SQL_KEYWORD_GLUED_SUFFIX_RE = re.compile(
    r"(?i)\A(?:SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|JOIN|VALUES|ORDER\s+BY|"
    r"GROUP\s+BY)\b"
)
_BACKTICK_WINDOW_DELIMITER_CHARS = "`'\"\n\r"
_BACKTICK_WINDOW_DELIMITER_RE = re.compile(r"[`'\"\n\r]")

_IMPLAUSIBLE_SQL_IDENTIFIER_CHARS_RE = re.compile(r"[\s/.;|&$()]")
_IMPLAUSIBLE_DOLLAR_PAREN_TOKEN_CHARS_RE = re.compile(r"[/.;|&$()]")
_BARE_SHELL_PARAMETER_NAME_RE = re.compile(
    r"\A[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z"
)
_SHELL_SPECIAL_PARAMETER_NAMES = frozenset({"ifs"})
_SHELL_PLAIN_IDENTIFIER_RE = re.compile(r"\A[A-Za-z_][\w-]*\Z")
_SHELL_SELECTOR_STRING_RE = re.compile(r"\A(['\"])[#.\[][^'\"]*\1\Z")
_SHELL_BRACE_SLICE_RE = re.compile(
    r"\A(?:[A-Za-z_]\w*|@|\*|#)?\s*:\s*-?\d+(?:\s*:\s*-?\d+)?\Z"
)
_SHELL_KNOWN_COMMAND_RE = re.compile(
    r"(?:(?i:ls|cat|id|whoami|uname|wget|curl|nc|ncat|netcat|socat|bash|sh|zsh|dash"
    r"|python|python3|perl|ruby|php|node|env|printenv|ifconfig|ip|ping|nslookup|dig"
    r"|sleep|echo|date|ps|who|w|last|groups|head|tail|base64|chmod|chown|kill|uptime"
    r"|nmap|telnet|ssh|scp|ftp|tftp|xxd|od|tr|sed|awk|find|grep|dir|type|reboot"
    r"|shutdown|halt|poweroff|systemctl|service|mount|umount|useradd|userdel|usermod"
    r"|passwd|su|sudo|crontab|nohup|chroot|dd|mkfifo|mknod|touch|mkdir|mv|cp|ln|tar"
    r"|gzip|gunzip|unzip|zip|openssl|powershell|pwsh|cmd|eval|exec|source|set|history"
    r"|msfconsole|msfvenom|certutil|bitsadmin|aria2c)"
    r"|(?-i:rm|pwd|hostname))\Z"
)
_AMBIGUOUS_BACKTICK_INJECTION_CONTEXTS = frozenset({"query_param", "url_path"})
_CTX_CMD_INJECTION_WITH_URL_PATH = frozenset(
    {"query_param", "header", "url_path", "request_body", "unknown"}
)
_CTX_URL_PATH_ONLY = frozenset({"url_path"})
_CTX_LOG4SHELL = frozenset(
    {"query_param", "header", "request_body", "url_path", "unknown"}
)

_BRACE_EXPANSION_ITEM_RE = r"[^{}\s,:'\"][^{},:'\"]*"
_BRACE_EXPANSION_COMMAND_RE = (
    r"(?:\A|[;&|]\s*|\$\()\{"
    + _BRACE_EXPANSION_ITEM_RE
    + r"(?:,(?:"
    + _BRACE_EXPANSION_ITEM_RE
    + r")?)+\}"
)
_QUOTE_SPLICE_CANDIDATE_RE = r"\w+(?:['\"]+\w+){1,10}"
_QUOTE_SPLICE_CANDIDATE_COMPILED_RE = re.compile(
    _QUOTE_SPLICE_CANDIDATE_RE, re.IGNORECASE
)

_GLOB_WILDCARD_ATOM_RE = r"[A-Za-z0-9_./*?-]*[?*][A-Za-z0-9_./*?-]*"
_GLOB_WILDCARD_PATH_RUN_RE = re.compile(r"[\w./*?-]+")
_GLOB_WILDCARD_CHAR_RE = re.compile(r"[?*]")


def _glob_wildcard_scan_matches(content: str, compiled: re.Pattern) -> list[re.Match]:
    if _GLOB_WILDCARD_CHAR_RE.search(content) is None:
        return []
    matches = []
    for run_match in _GLOB_WILDCARD_PATH_RUN_RE.finditer(content):
        run_start, run_end = run_match.start(), run_match.end()
        if _GLOB_WILDCARD_CHAR_RE.search(content, run_start, run_end) is None:
            continue
        match = compiled.match(content, run_start, run_end)
        if match is not None:
            matches.append(match)
    return matches


_PATTERN_SCAN_WINDOW_MATCHERS[_GLOB_WILDCARD_ATOM_RE] = _glob_wildcard_scan_matches

_PY_DANGEROUS_MODULE_RE = (
    r"__import__\(\s*['\"](?:os|subprocess|builtins|importlib)['\"]\s*\)"
    r"|\b(?:os|subprocess|builtins|importlib)\b"
)
_PY_DANGEROUS_METHOD_RE = (
    r"system|popen|exec|eval|call|run|Popen|check_output|check_call"
)
_PY_GETATTR_INDIRECTION_RE = (
    r"(?-i:\bgetattr\(\s*(?:" + _PY_DANGEROUS_MODULE_RE + r")\s*,\s*"
    r"['\"](?:" + _PY_DANGEROUS_METHOD_RE + r")['\"]\s*\)\s*\()"
)
_PY_VARS_INDIRECTION_RE = (
    r"(?-i:\bvars\(\s*(?:" + _PY_DANGEROUS_MODULE_RE + r")\s*\)\s*\[\s*"
    r"['\"](?:" + _PY_DANGEROUS_METHOD_RE + r")['\"]\s*\]\s*\()"
)

_SHELL_CHAIN_OPERATOR_RE = re.compile(r";|\|\||\||&&")
