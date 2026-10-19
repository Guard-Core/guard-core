import re

from guard_core.sync.handlers._suspatterns_ldap_ipv4 import (
    _LEGACY_IPV4_HOST_RE,
    _LOG4SHELL_JNDI_LOOKUP_RE,
)
from guard_core.sync.handlers._suspatterns_matchers import (
    _ATTR_EQUALS_WHITESPACE_RE,
    _FILE_UPLOAD_DANGEROUS_EXTENSION_RE,
    _FILE_UPLOAD_DECODED_TRUNCATION_RE,
    _FILE_UPLOAD_DOUBLE_EXTENSION_RE,
    _FILE_UPLOAD_TRUNCATION_RE,
    _HTML_TAG_OPEN_RE,
    _SQLI_LOAD_FILE_RE,
)
from guard_core.sync.handlers._suspatterns_named_floor import (
    CMS_TOKEN_PATTERN,
    NAMED_FLOOR_ROWS,
    NAMED_FLOOR_TOKEN_PATTERNS,
    SUPERSEDING_ROWS,
    V440_INICIO_ROW,
    V440_MANAGEMENT_ROW,
    V440_README_ROW,
)
from guard_core.sync.handlers._suspatterns_probe_chains import PROBE_CHAIN_ROW
from guard_core.sync.handlers._suspatterns_probe_names import (
    SCRIPT_NAMES_ANY_DEPTH_RES,
    SCRIPT_NAMES_UPLOAD_ONLY_RES,
)
from guard_core.sync.handlers._suspatterns_recall_rows import (
    _ABSOLUTE_PATH_VALUE_RE,
    _CMD_EXFILTRATION_RE,
    _CMD_EXTENDED_COMMAND_RE,
    _CMD_NEWLINE_COMMAND_DECODED_RE,
    _CMD_NEWLINE_COMMAND_RE,
    _CMD_PATH_CODE_EXECUTION_RE,
    _CMD_PATH_SEPARATOR_COMMAND_RE,
    _CMS_UPLOADS_DIRECTORY_RE,
    _CMS_UPLOADS_SCRIPT_RE,
    _DESERIALIZATION_YAML_PYTHON_RE,
    _FILE_INCLUSION_REMOTE_NULL_TERMINATED_RE,
    _FILE_UPLOAD_BARE_NAME_RE,
    _HTTP_SPLIT_CRLF_DECODED_RE,
    _PROTO_POLLUTION_CONSTRUCTOR_PROTOTYPE_RE,
    _RECON_CHANGELOG_BARE_RE,
    _RECON_SYSTEM_PROBE_FILES_RE,
    _SQLI_BLIND_SUBSTRING_RE,
    _SQLI_ERROR_BASED_RE,
    _SQLI_SCHEMA_SUBSELECT_RE,
    _SSRF_FRAGMENT_USERINFO_RE,
    _SSRF_WILDCARD_DNS_RE,
    _TEMPLATE_DUNDER_CHAIN_RE,
    _TEMPLATE_FREEMARKER_EXECUTE_RE,
    _TEMPLATE_OGNL_RE,
    _TEMPLATE_SPEL_SELECTION_RE,
    _TEMPLATE_VELOCITY_SET_RE,
)
from guard_core.sync.handlers._suspatterns_shell_sources import (
    _BRACE_EXPANSION_COMMAND_RE,
    _CMD_INJECTION_DOLLAR_SUBSTITUTION_RE,
    _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE,
    _CTX_CMD_INJECTION_WITH_URL_PATH,
    _CTX_LOG4SHELL,
    _CTX_URL_PATH_ONLY,
    _GLOB_WILDCARD_ATOM_RE,
    _GLUED_BACKTICK_CANDIDATE_RE,
    _GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE,
    _PY_GETATTR_INDIRECTION_RE,
    _PY_VARS_INDIRECTION_RE,
    _QUOTE_SPLICE_CANDIDATE_RE,
    _TEMPLATE_ASP_KEYWORD_RE,
    _TEMPLATE_CURLY_CALL_RE,
    _TEMPLATE_CURLY_KEYWORD_RE,
    _TEMPLATE_DOLLAR_BRACE_CALL_RE,
    _TEMPLATE_PERCENT_KEYWORD_RE,
)
from guard_core.sync.handlers._suspatterns_sources import (
    _CMD_INJECTION_NODE_CHILD_PROCESS_RE,
    _CMD_INJECTION_PHP_ASSERT_VARIABLE_RE,
    _CMD_INJECTION_PYTHON_EXEC_FAMILY_RE,
    _CMD_INJECTION_SHELL_DASH_FLAG_RE,
    _CTX_CMD_INJECTION,
    _CTX_CMS_PROBING,
    _CTX_CODE_INJECTION,
    _CTX_DESERIALIZATION,
    _CTX_DIR_TRAVERSAL,
    _CTX_FILE_INCLUSION,
    _CTX_FILE_UPLOAD,
    _CTX_HTTP_SPLIT,
    _CTX_LDAP,
    _CTX_NOSQL,
    _CTX_PATH_TRAVERSAL,
    _CTX_PROTO_POLLUTION,
    _CTX_RECON,
    _CTX_SENSITIVE_FILE,
    _CTX_SQLI,
    _CTX_SQLI_NARROW,
    _CTX_SSRF,
    _CTX_TEMPLATE,
    _CTX_XML,
    _CTX_XSS,
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
    _FILE_INCLUSION_BARE_HOST_RE,
    _FILE_INCLUSION_JSON_VALUE_RE,
    _HTTP_SPLIT_CRLF_RE,
    _JS_DYNAMIC_EVAL_BRACKET_RE,
    _JS_DYNAMIC_EVAL_CTOR_GADGET_RE,
    _JS_DYNAMIC_EVAL_FUNCTION_CTOR_RE,
    _JS_DYNAMIC_EVAL_TIMER_STRING_ARG_RE,
    _LDAP_NULL_BYTE_ATTR_RE,
    _LDAP_NULL_BYTE_BARE_RE,
    _LDAP_NULL_BYTE_DECODED_ATTR_RE,
    _LDAP_NULL_BYTE_DECODED_BARE_RE,
    _LDAP_PAREN_BREAKOUT_RE,
    _LDAP_PAREN_CONJUNCTION_RE,
    _LDAP_WILDCARD_CHAIN_RE,
    _LDAP_WILDCARD_EQUALS_RE,
    _MAP_FILE_PATH_RE,
    _PATH_ONLY_CHAR_RE,
    _PATH_ONLY_PREFIX_RE,
    _PATH_ONLY_SEP_RE,
    _PATH_ONLY_SUFFIX_RE,
    _PATH_TRAVERSAL_ENCODED_DOT_RE,
    _PATH_TRAVERSAL_SEMICOLON_SEP_RE,
    _PROTO_POLLUTION_PROTOTYPE_ASSIGN_RE,
    _PROTO_POLLUTION_SET_PROTOTYPE_OF_RE,
    _RECON_EXTENSION_PATH_RE,
    _SELECT_FROM_RE,
    _SELECT_STAR_RE,
    _SENSITIVE_SOURCE_EXTENSION_PATH_RE,
    _SQLI_COMMENT_TERMINATOR_RE,
    _SQLI_EXEC_STRONG_RE,
    _SQLI_ORDER_BY_STRONG_RE,
    _SQLI_ORDER_BY_TERMINATOR_RE,
    _SQLI_QUOTED_TAUTOLOGY_RE,
    _SQLI_TAUTOLOGY_RE,
    _SQLI_WAITFOR_RE,
    _SSRF_BARE_METADATA_ALIAS_RE,
    _SSTI_HASH_BRACE_SHAPE_RE,
    _SYSTEM_LOG_PATH_RE,
    _TERMINAL_PATH_SUFFIX_RE,
    _TOP_LEVEL_PATH_PREFIX_RE,
    _VERSION_ROOT_PATH_RE,
    _WHERE_CLAUSE_RE,
    _XML_XXE_PUBLIC_EXTERNAL_DTD_RE,
    _XSS_JS_SCHEME_CTRL_CHAR_RE,
    _embedded_prose_pattern,
    _nested_path_pattern,
    _path_only_pattern,
    _root_path_pattern,
)
from guard_core.sync.handlers._suspatterns_state import (
    _HTML_EVENT_HANDLER_ALTERNATION,
)

_UPLOAD_DIRECTORY_RE = r"(?:uploads?|files|images|media|tmp)"
_CTX_VALUE_PATH = frozenset({"query_param", "request_body", "unknown"})

BACKTICK_WHOLE_VALUE_RE = (
    r"\A\s*(?:[;&|]\s*)*`\s*(?:[A-Za-z0-9_./~]|\$[({])"
    r"(?:[^`\\\n]|\\.)*(?:\n\s*)?`"
    r"(?:\s*[;&|]\s*`\s*(?:[A-Za-z0-9_./~]|\$[({])"
    r"(?:[^`\\\n]|\\.)*(?:\n\s*)?`)*"
    r"\s*(?:[;&|]\s*)*\Z"
)

_SHELL_KEYWORD_COMMAND_RE = (
    r"[;|&]\s*(?:ls|cat|rm|id|whoami|uname|wget|curl|nc|netcat|socat|bash|sh|"
    r"python|perl)\b"
    r"(?!\s+(?:is|are|was|were|be|am|has|have|had|does|do|did|will|would|can|could"
    r"|should|may|might|and|or|the|a|an|to|of|in|on|for|as|at|by|it|its|that|this"
    r"|which|with|from|not|but|if|so)\s)"
)

NOISE_PRONE_PATTERN_SOURCES: frozenset[str] = frozenset(
    {
        _GLUED_BACKTICK_CANDIDATE_RE,
        _GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE,
        _CMD_INJECTION_DOLLAR_SUBSTITUTION_RE,
        _SHELL_KEYWORD_COMMAND_RE,
        _CMD_PATH_SEPARATOR_COMMAND_RE,
        _QUOTE_SPLICE_CANDIDATE_RE,
        _GLOB_WILDCARD_ATOM_RE,
        _TEMPLATE_DOLLAR_BRACE_CALL_RE,
        _SSTI_HASH_BRACE_SHAPE_RE,
        _LDAP_PAREN_CONJUNCTION_RE,
        # SQLi comment terminators span arbitrary whitespace between the quote
        # and the -- / # terminator, so they routinely fire inside text-decoded
        # binary bodies (e.g. "'\n--" byte runs in compressed payloads).
        _SQLI_COMMENT_TERMINATOR_RE,
    }
)

_PATTERN_DEFINITIONS: list[tuple[str, frozenset[str], str]] = [
    (r"<script[^>]*>[^<]*<\/script\s*>", _CTX_XSS, "xss"),
    (
        r"<script(?=[\s/>])(?![^<]{0,256}<\/script\s*>)(?:[^>]{0,256}\bsrc\s*="
        r"|[^>]{0,256}>\s*(?:(?:var|let|const|new|function|await|return)\s+)?"
        r"[\w$.]+\s*[(=.\[])",
        _CTX_XSS,
        "xss",
    ),
    (r"javascript:\s*[^\s]+", _CTX_XSS, "xss"),
    (_XSS_JS_SCHEME_CTRL_CHAR_RE, _CTX_XSS, "xss"),
    (
        r"(?:"
        + _HTML_TAG_OPEN_RE
        + r"(?:[^<>]*[^<>\s/])?(?<!=)(?<!=\")(?<!=')[\s/]+(?:"
        + _HTML_EVENT_HANDLER_ALTERNATION
        + r")\s*="
        + _ATTR_EQUALS_WHITESPACE_RE
        + r"(?:[\"'][^\"']*[\"']|[^\s>]+))",
        _CTX_XSS,
        "xss",
    ),
    (
        r"(?:"
        + _HTML_TAG_OPEN_RE
        + r"(?:[^<>]*[^<>\s])?\s+(?:href|src|data|action)\s*=[\s\"\']*"
        r"(?:javascript|vbscript|data):)",
        _CTX_XSS,
        "xss",
    ),
    (
        r"(?:"
        + _HTML_TAG_OPEN_RE
        + r"[^<>]*style\s*="
        + _ATTR_EQUALS_WHITESPACE_RE
        + r"[\"']?[^<>\"']*(?:expression|behavior|url)\s*\("
        r"[^)]*\))",
        _CTX_XSS,
        "xss",
    ),
    (r"(?:<object[^>]*>[\s\S]*<\/object\s*>)", _CTX_XSS, "xss"),
    (r"(?:<embed[^>]*>[\s\S]*<\/embed\s*>)", _CTX_XSS, "xss"),
    (r"(?:<applet[^>]*>[\s\S]*<\/applet\s*>)", _CTX_XSS, "xss"),
    (_SQLI_ERROR_BASED_RE, _CTX_SQLI, "sqli"),
    (_SQLI_SCHEMA_SUBSELECT_RE, _CTX_SQLI, "sqli"),
    (_SQLI_BLIND_SUBSTRING_RE, _CTX_SQLI, "sqli"),
    (_SELECT_FROM_RE, _CTX_SQLI, "sqli"),
    (_SELECT_STAR_RE, _CTX_SQLI, "sqli"),
    (_WHERE_CLAUSE_RE, _CTX_SQLI, "sqli"),
    (_SQLI_TAUTOLOGY_RE, _CTX_SQLI, "sqli"),
    (
        r"(?i)UNION\s+(?:ALL\s+)?SELECT\s*(?:/\*.{0,40}?\*/\s*){0,3}"
        r"(?:null\b|[\d@'\"`(*\[+~!-]"
        r"|[\w.$`\"]+\s*(?:,|\(|\bfrom\b|\)|--|#|/\*|;)"
        r"|(?:current_user|session_user|system_user|user|current_role"
        r"|current_schema|current_date|current_time|current_timestamp|localtime"
        r"|localtimestamp)\s*\Z)",
        _CTX_SQLI,
        "sqli",
    ),
    (
        r"(?i)('\s*(?:OR|AND)[\s(]*'?(?:[@:$][A-Za-z_]\w*|[\d\w]+)\s*"
        r"(?:LIKE|[<>]=?|=)[\s(]*'?(?:[@:$][A-Za-z_]\w*|[\d\w]+))",
        _CTX_SQLI,
        "sqli",
    ),
    (
        r"(?i)(UNION\s+(?:ALL\s+)?SELECT\s+NULL(?:[,\s]*NULL)*[,\s]*|"
        r"\(\s*SELECT\s+(?:@@|VERSION))",
        _CTX_SQLI,
        "sqli",
    ),
    (r"(?i)(?:INTO\s+(?:OUTFILE|DUMPFILE)\s+'[^']+')", _CTX_SQLI, "sqli"),
    (_SQLI_LOAD_FILE_RE, _CTX_SQLI, "sqli"),
    (r"(?i)(?:BENCHMARK\s*\(\s*\d+\s*,)", _CTX_SQLI, "sqli"),
    (
        r"(?i)(?:\A|[^\w\s]\s*|\b(?:AND|OR|XOR|NOT|IF|SELECT|THEN|ELSE|WHEN|CASE"
        r"|WHERE|HAVING|BY|AS|UNION|ALL|LIMIT|OFFSET)\s+)SLEEP\s*\(\s*\d+\s*\)",
        _CTX_SQLI,
        "sqli",
    ),
    (
        r"(?i)(?:\/\*![0-9]*\s*(?:OR|AND|UNION|SELECT|INSERT|DELETE|DROP|"
        r"CONCAT|CHAR|UPDATE)\b)",
        _CTX_SQLI,
        "sqli",
    ),
    (r"\w/\*(?!!)[^*]*\*/\w", _CTX_SQLI_NARROW, "sqli"),
    (_SQLI_QUOTED_TAUTOLOGY_RE, _CTX_SQLI, "sqli"),
    (
        r"(?i);\s*(?:DROP|TRUNCATE|ALTER|CREATE)\s+(?:TABLE|DATABASE|SCHEMA)\b",
        _CTX_SQLI,
        "sqli",
    ),
    (
        r"(?i);\s*(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|"
        r"SELECT\b[^;]*?\bFROM\b|REPLACE\s+INTO)\b",
        _CTX_SQLI,
        "sqli",
    ),
    (
        r"(?i)\bEXEC(?:UTE)?\s+(?:xp_\w+|sp_\w+)",
        _CTX_SQLI_NARROW,
        "sqli",
    ),
    (_SQLI_EXEC_STRONG_RE, _CTX_SQLI, "sqli"),
    (_SQLI_ORDER_BY_TERMINATOR_RE, _CTX_SQLI_NARROW, "sqli"),
    (_SQLI_ORDER_BY_STRONG_RE, _CTX_SQLI, "sqli"),
    (_SQLI_COMMENT_TERMINATOR_RE, _CTX_SQLI, "sqli"),
    (_SQLI_WAITFOR_RE, _CTX_SQLI, "sqli"),
    (r"(?:\.\.\/|\.\.\\)(?:\.\.\/|\.\.\\)+", _CTX_DIR_TRAVERSAL, "dir_traversal"),
    (_DIR_TRAVERSAL_ETC_SENSITIVE_RE, _CTX_DIR_TRAVERSAL, "dir_traversal"),
    (
        _embedded_prose_pattern(
            r"etc/(?:passwd|shadow|group|hosts|motd|issue|mysql/my\.cnf"
            r"|ssh/ssh_config)"
        ),
        _CTX_DIR_TRAVERSAL,
        "dir_traversal",
    ),
    (_DIR_TRAVERSAL_WINDOWS_INI_RE, _CTX_DIR_TRAVERSAL, "dir_traversal"),
    (_DIR_TRAVERSAL_PROC_ENVIRON_RE, _CTX_DIR_TRAVERSAL, "dir_traversal"),
    (_DIR_TRAVERSAL_VAR_LOG_RE, _CTX_DIR_TRAVERSAL, "dir_traversal"),
    (_PATH_TRAVERSAL_SEMICOLON_SEP_RE, _CTX_DIR_TRAVERSAL, "dir_traversal"),
    (
        r";\s*(?:ls|cat|rm|chmod|chown|wget|curl|nc|netcat|ping|telnet)\s+"
        r"-[a-zA-Z]+\s+",
        _CTX_CMD_INJECTION,
        "cmd_injection",
    ),
    (
        r"\|\s*(?:wget|curl|fetch|lwp-download|lynx|links|GET)\s+",
        _CTX_CMD_INJECTION,
        "cmd_injection",
    ),
    (_CMD_EXTENDED_COMMAND_RE, _CTX_CMD_INJECTION, "cmd_injection"),
    (_CMD_NEWLINE_COMMAND_RE, _CTX_CMD_INJECTION, "cmd_injection"),
    (_CMD_NEWLINE_COMMAND_DECODED_RE, _CTX_CMD_INJECTION, "cmd_injection"),
    (_CMD_EXFILTRATION_RE, _CTX_CMD_INJECTION, "cmd_injection"),
    (_CMD_PATH_SEPARATOR_COMMAND_RE, _CTX_URL_PATH_ONLY, "cmd_injection"),
    (_CMD_PATH_CODE_EXECUTION_RE, _CTX_URL_PATH_ONLY, "cmd_injection"),
    (_ABSOLUTE_PATH_VALUE_RE, _CTX_VALUE_PATH, "dir_traversal"),
    (
        _CMD_INJECTION_DOLLAR_SUBSTITUTION_RE,
        _CTX_CMD_INJECTION,
        "cmd_injection",
    ),
    (BACKTICK_WHOLE_VALUE_RE, _CTX_CMD_INJECTION, "cmd_injection"),
    (
        _GLUED_BACKTICK_CANDIDATE_RE,
        _CTX_CMD_INJECTION_WITH_URL_PATH,
        "cmd_injection",
    ),
    (
        _GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE,
        _CTX_CMD_INJECTION_WITH_URL_PATH,
        "cmd_injection",
    ),
    (
        _LOG4SHELL_JNDI_LOOKUP_RE,
        _CTX_LOG4SHELL,
        "cmd_injection",
    ),
    (
        _CMD_INJECTION_SHELL_DASH_FLAG_RE,
        _CTX_CMD_INJECTION,
        "cmd_injection",
    ),
    (
        r"(?:\A|[;|&])\s*[^=\s;|&]+=[^\s;|&]+\s+(?:/?(?:[\w.-]+/)*env\s+)?/?(?:[\w.-]+/)*"
        r"(?:bash|sh|ksh|csh|tsch|zsh|ash)\s+-[a-zA-Z]+",
        _CTX_CMD_INJECTION,
        "cmd_injection",
    ),
    (
        _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE,
        _CTX_CMD_INJECTION,
        "cmd_injection",
    ),
    (
        r"\b(?:eval|system|exec|shell_exec|passthru|popen|proc_open|create_function)\s*\(",
        _CTX_CMD_INJECTION,
        "cmd_injection",
    ),
    (
        _CMD_INJECTION_NODE_CHILD_PROCESS_RE,
        _CTX_CMD_INJECTION,
        "cmd_injection",
    ),
    (
        _CMD_INJECTION_PHP_ASSERT_VARIABLE_RE,
        _CTX_CMD_INJECTION,
        "cmd_injection",
    ),
    (
        _CMD_INJECTION_PYTHON_EXEC_FAMILY_RE,
        _CTX_CMD_INJECTION,
        "cmd_injection",
    ),
    (
        _JS_DYNAMIC_EVAL_FUNCTION_CTOR_RE,
        _CTX_CMD_INJECTION,
        "cmd_injection",
    ),
    (
        _JS_DYNAMIC_EVAL_BRACKET_RE,
        _CTX_CMD_INJECTION,
        "cmd_injection",
    ),
    (
        _JS_DYNAMIC_EVAL_CTOR_GADGET_RE,
        _CTX_CMD_INJECTION,
        "cmd_injection",
    ),
    (
        _JS_DYNAMIC_EVAL_TIMER_STRING_ARG_RE,
        _CTX_CMD_INJECTION,
        "cmd_injection",
    ),
    (
        _SHELL_KEYWORD_COMMAND_RE,
        _CTX_CMD_INJECTION,
        "cmd_injection",
    ),
    (
        r"(?i)\b(?:nc|netcat|ncat)\s+-[a-z]*e\b|/dev/tcp/\d",
        _CTX_CMD_INJECTION,
        "cmd_injection",
    ),
    (
        _BRACE_EXPANSION_COMMAND_RE,
        _CTX_CMD_INJECTION,
        "cmd_injection",
    ),
    (
        _QUOTE_SPLICE_CANDIDATE_RE,
        _CTX_CMD_INJECTION,
        "cmd_injection",
    ),
    (
        _GLOB_WILDCARD_ATOM_RE,
        _CTX_CMD_INJECTION,
        "cmd_injection",
    ),
    (
        r"(?:php|data|zip|rar|file|glob|expect|input|phpinfo|zlib|phar|ssh2|"
        r"rar|ogg|expect)://[^\s]+",
        _CTX_FILE_INCLUSION,
        "file_inclusion",
    ),
    (
        _FILE_INCLUSION_BARE_HOST_RE,
        _CTX_FILE_INCLUSION,
        "file_inclusion",
    ),
    (
        r"=(?:https?|ftp):\/\/[^\s'\"<>]+\/[^\s'\"<>\/]*\.(?:phtml|php[3-5]?|"
        r"phar|jsp|aspx?|pl|py|txt|inc)(?![a-zA-Z0-9])",
        _CTX_FILE_INCLUSION,
        "file_inclusion",
    ),
    (
        _FILE_INCLUSION_JSON_VALUE_RE,
        _CTX_FILE_INCLUSION,
        "file_inclusion",
    ),
    (
        r"\([\s]*[|&][\s]*\([^)(]+=[*]",
        _CTX_LDAP,
        "ldap",
    ),
    (_LDAP_WILDCARD_EQUALS_RE, _CTX_LDAP, "ldap"),
    (_LDAP_PAREN_BREAKOUT_RE, _CTX_LDAP, "ldap"),
    (_LDAP_PAREN_CONJUNCTION_RE, _CTX_LDAP, "ldap"),
    (_LDAP_WILDCARD_CHAIN_RE, _CTX_LDAP, "ldap"),
    (_LDAP_NULL_BYTE_ATTR_RE, _CTX_LDAP, "ldap"),
    (_LDAP_NULL_BYTE_BARE_RE, _CTX_LDAP, "ldap"),
    (_LDAP_NULL_BYTE_DECODED_ATTR_RE, _CTX_LDAP, "ldap"),
    (_LDAP_NULL_BYTE_DECODED_BARE_RE, _CTX_LDAP, "ldap"),
    (r"<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>", _CTX_XML, "xml"),
    (_XML_XXE_PUBLIC_EXTERNAL_DTD_RE, _CTX_XML, "xml"),
    (r"(?:<!\[CDATA\[.*?\]\]>)", _CTX_XML, "xml"),
    (r"<!DOCTYPE[^>\[]*\[[\s\S]*?<!ENTITY", _CTX_XML, "xml"),
    (
        r"(?:^|\s|/)(?:(?<=://)[^\s/@]*@)?(?:localhost\.?|127\.0\.0\.1|0\.0\.0\.0|"
        r"\[::(?:\d*)\]|\[::ffff:127\.0\.0\.1\]|169\.254(?:\.\d{1,3}){2}|"
        r"192\.168(?:\.\d{1,3}){2}|"
        r"10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2[0-9]|3[01])(?:\.\d{1,3}){2}|"
        r"metadata\.google\.internal|metadata\.goog|100\.100\.100\.200)"
        r"(?::\d+)?(?:\s|$|/)",
        _CTX_SSRF,
        "ssrf",
    ),
    (_LEGACY_IPV4_HOST_RE, _CTX_SSRF, "ssrf"),
    (_SSRF_WILDCARD_DNS_RE, _CTX_SSRF, "ssrf"),
    (_SSRF_FRAGMENT_USERINFO_RE, _CTX_SSRF, "ssrf"),
    (r"(?:file|dict|gopher|jar|tftp)://[^\s]+", _CTX_SSRF, "ssrf"),
    (
        _FILE_INCLUSION_REMOTE_NULL_TERMINATED_RE,
        _CTX_FILE_INCLUSION,
        "file_inclusion",
    ),
    (r"://[^/\s@]*@[^/\s@]*@", _CTX_SSRF, "ssrf"),
    (_SSRF_BARE_METADATA_ALIAS_RE, _CTX_SSRF, "ssrf"),
    (
        r"\{\s*\$(?:where|gt|lt|ne|eq|regex|in|nin|all|size|exists|type|mod|"
        r"options):",
        _CTX_NOSQL,
        "nosql",
    ),
    (r"(?:\{\s*\$[a-zA-Z]+\s*:\s*(?:\{|\[))", _CTX_NOSQL, "nosql"),
    (
        r'"\$(?:where|regex|expr|jsonSchema|function|accumulator|type|exists|size)"\s*:',
        _CTX_NOSQL,
        "nosql",
    ),
    (
        r'"\$(?:gt|gte|lt|lte|ne|eq|in|nin|all|mod)"' r'\s*:\s*(?:""|null|\{|\[)',
        _CTX_NOSQL,
        "nosql",
    ),
    (
        r'"[^"]+"\s*:\s*\{\s*"\$(?:ne|eq)"\s*:\s*(?:true|false)',
        _CTX_NOSQL,
        "nosql",
    ),
    (
        r"\[\$(?:where|gt|gte|lt|lte|ne|eq|regex|in|nin|nor|and|or|not|all|"
        r"size|exists|type|mod|options|expr|function|elemMatch)\]",
        _CTX_NOSQL,
        "nosql",
    ),
    (
        _FILE_UPLOAD_DANGEROUS_EXTENSION_RE,
        _CTX_FILE_UPLOAD,
        "file_upload",
    ),
    (
        _FILE_UPLOAD_DOUBLE_EXTENSION_RE,
        _CTX_FILE_UPLOAD,
        "file_upload",
    ),
    (
        _FILE_UPLOAD_TRUNCATION_RE,
        _CTX_FILE_UPLOAD,
        "file_upload",
    ),
    (
        _FILE_UPLOAD_DECODED_TRUNCATION_RE,
        _CTX_FILE_UPLOAD,
        "file_upload",
    ),
    (_FILE_UPLOAD_BARE_NAME_RE, _CTX_FILE_UPLOAD, "file_upload"),
    (_PATH_TRAVERSAL_ENCODED_DOT_RE, _CTX_PATH_TRAVERSAL, "path_traversal"),
    (
        _TEMPLATE_CURLY_KEYWORD_RE,
        _CTX_TEMPLATE,
        "template",
    ),
    (
        _TEMPLATE_PERCENT_KEYWORD_RE,
        _CTX_TEMPLATE,
        "template",
    ),
    (
        _TEMPLATE_ASP_KEYWORD_RE,
        _CTX_TEMPLATE,
        "template",
    ),
    (
        _TEMPLATE_DOLLAR_BRACE_CALL_RE,
        _CTX_TEMPLATE,
        "template",
    ),
    (
        _TEMPLATE_CURLY_CALL_RE,
        _CTX_TEMPLATE,
        "template",
    ),
    (_SSTI_HASH_BRACE_SHAPE_RE, _CTX_TEMPLATE, "template"),
    (_TEMPLATE_DUNDER_CHAIN_RE, _CTX_TEMPLATE, "template"),
    (_TEMPLATE_FREEMARKER_EXECUTE_RE, _CTX_TEMPLATE, "template"),
    (_TEMPLATE_VELOCITY_SET_RE, _CTX_TEMPLATE, "template"),
    (_TEMPLATE_SPEL_SELECTION_RE, _CTX_TEMPLATE, "template"),
    (_TEMPLATE_OGNL_RE, _CTX_TEMPLATE, "template"),
    (_HTTP_SPLIT_CRLF_RE, _CTX_HTTP_SPLIT, "http_split"),
    (_HTTP_SPLIT_CRLF_DECODED_RE, _CTX_HTTP_SPLIT, "http_split"),
    (
        _path_only_pattern(r"\.env(?:\.\w+)?"),
        _CTX_SENSITIVE_FILE,
        "sensitive_file",
    ),
    (
        _embedded_prose_pattern(r"\.env(?:\.\w+)?"),
        _CTX_SENSITIVE_FILE,
        "sensitive_file",
    ),
    (
        _path_only_pattern(
            r"(?:(?!config)[\w-])*config[\w-]*\.(?:env|yml|yaml|json|toml|ini|xml|conf)"
        ),
        _CTX_SENSITIVE_FILE,
        "sensitive_file",
    ),
    (
        _MAP_FILE_PATH_RE,
        _CTX_SENSITIVE_FILE,
        "sensitive_file",
    ),
    (
        _SENSITIVE_SOURCE_EXTENSION_PATH_RE,
        _CTX_SENSITIVE_FILE,
        "sensitive_file",
    ),
    (
        _path_only_pattern(
            r"(?:(?:local_settings|settings|config|secrets|configuration)\.py"
            r"|(?:wp-config|config|configuration)\.php"
            r"|database\.ya?ml|appsettings(?:\.\w+)?\.json)"
        ),
        _CTX_SENSITIVE_FILE,
        "sensitive_file",
    ),
    (
        _path_only_pattern(r"(?:c99|r57)\.php"),
        _CTX_RECON,
        "recon",
    ),
    (
        rf"\A{_PATH_ONLY_SEP_RE}"
        rf"(?:(?!{_UPLOAD_DIRECTORY_RE}{_PATH_ONLY_SEP_RE})"
        rf"{_PATH_ONLY_CHAR_RE}+{_PATH_ONLY_SEP_RE})*"
        rf"{_UPLOAD_DIRECTORY_RE}{_PATH_ONLY_SEP_RE}"
        rf"(?:(?!(?:shell|cmd)\.php(?:{_PATH_ONLY_SEP_RE}|\Z))"
        rf"{_PATH_ONLY_CHAR_RE}+{_PATH_ONLY_SEP_RE})*(?:shell|cmd)\.php"
        + _PATH_ONLY_SUFFIX_RE,
        _CTX_RECON,
        "recon",
    ),
    (
        rf"\A{_PATH_ONLY_SEP_RE}?(?:{_PATH_ONLY_CHAR_RE}+{_PATH_ONLY_SEP_RE})*"
        rf"phpunit{_PATH_ONLY_SEP_RE}(?:{_PATH_ONLY_CHAR_RE}+{_PATH_ONLY_SEP_RE})*"
        rf"src{_PATH_ONLY_SEP_RE}Util{_PATH_ONLY_SEP_RE}PHP{_PATH_ONLY_SEP_RE}"
        r"eval-stdin\.php" + _PATH_ONLY_SUFFIX_RE,
        _CTX_RECON,
        "recon",
    ),
    (
        _path_only_pattern(r"\.(?:git|svn|hg|bzr)"),
        _CTX_SENSITIVE_FILE,
        "sensitive_file",
    ),
    (
        _embedded_prose_pattern(r"\.(?:git|svn|hg|bzr)"),
        _CTX_SENSITIVE_FILE,
        "sensitive_file",
    ),
    (
        _PATH_ONLY_PREFIX_RE + rf"{_PATH_ONLY_CHAR_RE}*\.\w+~(?:\?\S*)?\s*\Z",
        _CTX_SENSITIVE_FILE,
        "sensitive_file",
    ),
    (_CMS_UPLOADS_SCRIPT_RE, _CTX_CMS_PROBING, "cms_probing"),
    (_CMS_UPLOADS_DIRECTORY_RE, _CTX_CMS_PROBING, "cms_probing"),
    (
        _path_only_pattern(
            r"(?:wp-(?:admin|login|includes|config)|administrator|xmlrpc)"
            r"\.?(?:php)?"
        ),
        _CTX_CMS_PROBING,
        "cms_probing",
    ),
    (
        rf"\A{_PATH_ONLY_SEP_RE}?"
        rf"(?:(?!wp-content\.?(?:php)?(?:{_PATH_ONLY_SEP_RE}|\Z))"
        rf"{_PATH_ONLY_CHAR_RE}+{_PATH_ONLY_SEP_RE})*"
        rf"wp-content(?!{_PATH_ONLY_SEP_RE}uploads(?:{_PATH_ONLY_SEP_RE}|\Z))"
        r"\.?(?:php)?" + _PATH_ONLY_SUFFIX_RE,
        _CTX_CMS_PROBING,
        "cms_probing",
    ),
    (
        _embedded_prose_pattern(
            r"(?:wp-(?:admin|login|content|includes|config)|administrator|xmlrpc)"
            r"\.?(?:php)?"
        ),
        _CTX_CMS_PROBING,
        "cms_probing",
    ),
    (
        _path_only_pattern(r"(?:phpinfo|info|test|php_info)\.php"),
        _CTX_CMS_PROBING,
        "cms_probing",
    ),
    (
        _embedded_prose_pattern(r"(?:phpinfo|info|test|php_info)\.php"),
        _CTX_CMS_PROBING,
        "cms_probing",
    ),
    (
        _path_only_pattern(
            rf"{_PATH_ONLY_CHAR_RE}*\.(?:bak|backup|old|orig|save|swp|swo|tmp|temp)"
        ),
        _CTX_CMS_PROBING,
        "cms_probing",
    ),
    (
        _path_only_pattern(
            r"(?:\.htaccess|\.htpasswd|\.DS_Store|Thumbs\.db"
            r"|\.npmrc|\.dockerenv|web\.config)"
        ),
        _CTX_CMS_PROBING,
        "cms_probing",
    ),
    (
        _embedded_prose_pattern(
            r"(?:\.htaccess|\.htpasswd|\.DS_Store|Thumbs\.db"
            r"|\.npmrc|\.dockerenv|web\.config)"
        ),
        _CTX_CMS_PROBING,
        "cms_probing",
    ),
    (
        _RECON_EXTENSION_PATH_RE,
        _CTX_RECON,
        "recon",
    ),
    (_SYSTEM_LOG_PATH_RE, _CTX_URL_PATH_ONLY, "recon"),
    (_VERSION_ROOT_PATH_RE, _CTX_URL_PATH_ONLY, "recon"),
    (
        _nested_path_pattern(r"config_dump"),
        _CTX_RECON,
        "recon",
    ),
    (
        rf"\A{_PATH_ONLY_SEP_RE}credentials" + _PATH_ONLY_SUFFIX_RE,
        _CTX_RECON,
        "recon",
    ),
    (
        rf"\A{_PATH_ONLY_SEP_RE}system" + _TERMINAL_PATH_SUFFIX_RE,
        _CTX_RECON,
        "recon",
    ),
    (_RECON_SYSTEM_PROBE_FILES_RE, _CTX_RECON, "recon"),
    *((names_row, _CTX_RECON, "recon") for names_row in SCRIPT_NAMES_ANY_DEPTH_RES),
    *((names_row, _CTX_RECON, "recon") for names_row in SCRIPT_NAMES_UPLOAD_ONLY_RES),
    (PROBE_CHAIN_ROW, _CTX_RECON, "recon"),
    (_RECON_CHANGELOG_BARE_RE, _CTX_RECON, "recon"),
    (
        _path_only_pattern(r"(?:actuator|server-status|telescope)"),
        _CTX_RECON,
        "recon",
    ),
    (
        r"(?:CSCOE|dana-(?:na|cached)|sslvpn|RDWeb|/owa/|/ecp/"
        r"|global-protect|ssl-vpn/|svpn/|sonicui|/remote/login"
        r"|myvpn|vpntunnel|versa/login)",
        _CTX_RECON,
        "recon",
    ),
    (
        _path_only_pattern(
            r"(?:geoserver|confluence|nifi|ScadaBR|pandora_console"
            r"|centreon|kylin|decisioncenter|evox|MagicInfo|metasys"
            r"|officescan|helpdesk|ignite)",
            trailing=rf"(?:[.\-]{_PATH_ONLY_CHAR_RE}*)?",
        ),
        _CTX_RECON,
        "recon",
    ),
    (
        _path_only_pattern(r"cgi-(?:bin|mod)"),
        _CTX_RECON,
        "recon",
    ),
    (
        _path_only_pattern(r"(?:HNAP1|IPCamDesc\.xml|SDK/webLanguage)"),
        _CTX_RECON,
        "recon",
    ),
    (
        rf"\A{_PATH_ONLY_SEP_RE}(?:language|languages){_PATH_ONLY_SEP_RE}"
        r"[^/\\\s]*[;&|`$<>(){}'\"]",
        _CTX_RECON,
        "recon",
    ),
    (
        _root_path_pattern(
            r"(?:readme\.txt|README\.md|CHANGELOG\.\w+|pom\.xml"
            r"|build\.gradle|appsettings\.json|crossdomain\.xml)",
            trailing=rf"(?:\.{_PATH_ONLY_CHAR_RE}*)?",
        ),
        _CTX_RECON,
        "recon",
    ),
    (
        _path_only_pattern(
            r"(?:sap|ise|nidp|cslu|rustfs|developmentserver"
            r"|fog/management|lms/db|json/login_session|sms_mp"
            r"|plugin/webs_model|wsman|am_bin)"
        ),
        _CTX_RECON,
        "recon",
    ),
    (r"(?:nmaplowercheck|nice\s+ports|Trinity\.txt)", _CTX_RECON, "recon"),
    (
        _path_only_pattern(r"\.(?:openclaw|clawdbot)"),
        _CTX_RECON,
        "recon",
    ),
    (
        _TOP_LEVEL_PATH_PREFIX_RE
        + r"(?:default|inicio|indice|localstart)"
        + rf"(?:\.{_PATH_ONLY_CHAR_RE}*)?"
        + _TERMINAL_PATH_SUFFIX_RE,
        _CTX_RECON,
        "recon",
    ),
    (
        _root_path_pattern(r"inicio\.html?"),
        _CTX_RECON,
        "recon",
    ),
    (
        _path_only_pattern(
            r"(?:\.streamlit|\.gpt-pilot|\.aider|\.cursor"
            r"|\.windsurf|\.copilot|\.devcontainer)"
        ),
        _CTX_RECON,
        "recon",
    ),
    (
        _path_only_pattern(
            r"(?:docker-compose|Dockerfile|Makefile|Vagrantfile"
            r"|Jenkinsfile|Procfile)(?:\.ya?ml)?"
        ),
        _CTX_RECON,
        "recon",
    ),
    (
        _path_only_pattern(
            rf"{_PATH_ONLY_CHAR_RE}*(?:secrets?|credentials?)"
            r"\.(?:py|json|yml|yaml|toml|txt|env|xml|conf|cfg)"
        ),
        _CTX_RECON,
        "recon",
    ),
    (
        _path_only_pattern(r"autodiscover"),
        _CTX_RECON,
        "recon",
    ),
    (
        _path_only_pattern(r"dns-query"),
        _CTX_RECON,
        "recon",
    ),
    (
        _path_only_pattern(r"\.git/(?:refs|index|HEAD|objects|logs)"),
        _CTX_RECON,
        "recon",
    ),
    (
        r"(?:__proto__|constructor)\s*(?:\[\s*[\"']prototype[\"']\s*\]|\.\s*prototype)|[\"']__proto__[\"']\s*:",
        _CTX_PROTO_POLLUTION,
        "proto_pollution",
    ),
    (
        r"__proto__\s*(?:\[|\.)|\[\s*[\"']?__proto__[\"']?\s*\]|"
        r"constructor\s*\[\s*[\"']?prototype[\"']?\s*\]|"
        r"\[\s*[\"']?constructor[\"']?\s*\]\s*\[\s*[\"']?prototype[\"']?\s*\]",
        _CTX_PROTO_POLLUTION,
        "proto_pollution",
    ),
    (
        _PROTO_POLLUTION_CONSTRUCTOR_PROTOTYPE_RE,
        _CTX_PROTO_POLLUTION,
        "proto_pollution",
    ),
    (
        _PROTO_POLLUTION_PROTOTYPE_ASSIGN_RE,
        _CTX_PROTO_POLLUTION,
        "proto_pollution",
    ),
    (
        _PROTO_POLLUTION_SET_PROTOTYPE_OF_RE,
        _CTX_PROTO_POLLUTION,
        "proto_pollution",
    ),
    (
        r"System\.Diagnostics\.Process\.Start\s*\(|System\.Reflection\.|Assembly\.Load\s*\(",
        _CTX_CODE_INJECTION,
        "code_injection",
    ),
    (
        _PY_GETATTR_INDIRECTION_RE,
        _CTX_CODE_INJECTION,
        "code_injection",
    ),
    (
        _PY_VARS_INDIRECTION_RE,
        _CTX_CODE_INJECTION,
        "code_injection",
    ),
    (_DESERIALIZATION_JAVA_B64_RE, _CTX_DESERIALIZATION, "deserialization"),
    (_DESERIALIZATION_DOTNET_B64_RE, _CTX_DESERIALIZATION, "deserialization"),
    (_DESERIALIZATION_PICKLE_B64_RE, _CTX_DESERIALIZATION, "deserialization"),
    (_DESERIALIZATION_RUBY_B64_RE, _CTX_DESERIALIZATION, "deserialization"),
    (
        _DESERIALIZATION_PICKLE_OS_GLOBAL_RE,
        _CTX_DESERIALIZATION,
        "deserialization",
    ),
    (r"c__builtin__", _CTX_DESERIALIZATION, "deserialization"),
    (r"csubprocess", _CTX_DESERIALIZATION, "deserialization"),
    (r"cposix", _CTX_DESERIALIZATION, "deserialization"),
    (
        _DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE,
        _CTX_DESERIALIZATION,
        "deserialization",
    ),
    (_DESERIALIZATION_YAML_PYTHON_RE, _CTX_DESERIALIZATION, "deserialization"),
    (r'O:\d+:"', _CTX_DESERIALIZATION, "deserialization"),
    (r'C:\d+:"', _CTX_DESERIALIZATION, "deserialization"),
    (r'E:\d+:"', _CTX_DESERIALIZATION, "deserialization"),
    (r"<ObjectDataProvider\b", _CTX_DESERIALIZATION, "deserialization"),
    *NAMED_FLOOR_ROWS,
]

# Whole-value recon rows whose leading path separator is optional: outside a URL
# path they match bare words such as "default" or "README.md", not only probe paths.
RECON_OPTIONAL_SEPARATOR_PATTERN_SOURCES: frozenset[str] = frozenset(
    source
    for source, _contexts, category in _PATTERN_DEFINITIONS
    if category == "recon" and source.startswith(_TOP_LEVEL_PATH_PREFIX_RE)
)

# Path-anchored probe rows that a URL path clears when the app declares the same
# page as a route (D-75): every sensitive_file, recon and cms_probing row that has
# no gate of its own, except the unconditional chain row of named probes.
for _source, _contexts, _category in _PATTERN_DEFINITIONS:
    if _category == "cms_probing" and (
        "wp-(?:admin|login|includes|config)|administrator|xmlrpc" in _source
        or "wp-content(?!" in _source
    ):
        NAMED_FLOOR_TOKEN_PATTERNS.setdefault(_source, CMS_TOKEN_PATTERN)

# A narrow root row that reports the same path unconditionally supersedes the
# gated v4.4.0 row for it, so the path is reported once.
_NARROW_ROW_MARKERS: dict[str, tuple[str, ...]] = {
    V440_README_ROW: (r"CHANGELOG\.\w+", r"(?-i:CHANGELOG"),
    V440_INICIO_ROW: (r"\A[/\\]?inicio",),
    V440_MANAGEMENT_ROW: ("config_dump", r"\A[/\\]credentials"),
}
for _floor, _markers in _NARROW_ROW_MARKERS.items():
    SUPERSEDING_ROWS[_floor] = tuple(
        re.compile(_source, re.IGNORECASE)
        for _source, _contexts, _category in _PATTERN_DEFINITIONS
        if _category == "recon"
        and _source != _floor
        and any(marker in _source for marker in _markers)
    )

ROUTE_GATED_PATH_SOURCES: frozenset[str] = frozenset(
    source
    for source, _contexts, category in _PATTERN_DEFINITIONS
    if category in {"sensitive_file", "recon", "cms_probing"}
    and source.startswith(r"\A[/\\]")
    and source
    not in {
        PROBE_CHAIN_ROW,
        _SENSITIVE_SOURCE_EXTENSION_PATH_RE,
        _RECON_EXTENSION_PATH_RE,
        _MAP_FILE_PATH_RE,
        _VERSION_ROOT_PATH_RE,
        _SYSTEM_LOG_PATH_RE,
        *NAMED_FLOOR_TOKEN_PATTERNS,
    }
)

# Recon rows additionally scanned against the signal-preserving raw view. The
# processed views fold LDAP hex escapes ("\de" -> "Þ") before the pattern
# tables run, so separator-prefixed probes such as "\default" or
# "\default.asp" never reach a recon row there. The raw view keeps them
# intact; the leading-separator gate still decides which matches are probes,
# so bare words stay innocent exactly as on the processed views. The file
# exfiltration command row joins them: the base64 candidate decoder rewrites an
# option such as "--data-binary" into junk on the processed views, and the
# absolute path row joins them for the same reason ("D:\data" becomes "D:Úta").
DETECTION_RECON_RAW_VIEW_PATTERN_SOURCES: frozenset[str] = frozenset(
    source
    for source, _contexts, category in _PATTERN_DEFINITIONS
    if category == "recon"
) | {_CMD_EXFILTRATION_RE, _ABSOLUTE_PATH_VALUE_RE}
