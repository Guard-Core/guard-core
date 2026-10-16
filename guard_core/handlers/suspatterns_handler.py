import asyncio as asyncio
import concurrent as concurrent
import functools as functools
import io as io
import ipaddress as ipaddress
import logging
import pickle as pickle
import re
import sys as sys
import time
import warnings
from collections.abc import Callable as Callable
from collections.abc import Iterator as Iterator
from datetime import datetime as datetime
from datetime import timezone as timezone
from typing import Any
from typing import NamedTuple as NamedTuple

from guard_core._utils.detection_scan import _context_header_is_semantic_excluded
from guard_core.detection_engine import (
    ContentPreprocessor,
    PatternCompiler,
    PerformanceMonitor,
    SemanticAnalyzer,
)
from guard_core.detection_engine import (
    looks_like_binary_content as looks_like_binary_content,
)
from guard_core.detection_engine.compiler import (
    report_scan_success as report_scan_success,
)
from guard_core.detection_engine.compiler import (
    report_scan_timeout as report_scan_timeout,
)
from guard_core.detection_engine.compiler import (
    shared_regex_executor as shared_regex_executor,
)
from guard_core.detection_engine.scan_window import (
    bounded_finditer as bounded_finditer,
)
from guard_core.handlers._suspatterns_ldap_ipv4 import (
    _LEGACY_IPV4_BLOCKED_NETWORKS,
    _LEGACY_IPV4_HOST_RE,
    _LEGACY_IPV4_PART_RE,
    _LOG4SHELL_JNDI_LOOKUP_RE,
    _MIN_BARE_DECIMAL_LEGACY_IPV4,
    ALWAYS_SCAN_HEADER_PATTERNS,
    _decode_legacy_ipv4_host,
    _decode_legacy_ipv4_part,
    _is_ambiguous_bare_decimal_port,
    _is_bare_decimal_legacy_ipv4_part,
    _is_blocked_legacy_ipv4,
    _ldap_breakout_backward_window,
    _ldap_breakout_forward_window,
    _ldap_filter_expression_forward_extent,
    _ldap_next_candidate_scan_limit,
    _ldap_paren_conjunction_is_injection,
    _ldap_wildcard_chain_is_injection,
    _legacy_ipv4_match_is_blocked,
)
from guard_core.handlers._suspatterns_matchers import (
    _ATTR_EQUALS_WHITESPACE_RE,
    _BRACE_EXPANSION_LETTER_RE,
    _BRACE_EXPANSION_WORD_ITEM_RE,
    _CMD_INJECTION_ASSIGNMENT_PREFIX_RE,
    _CMD_INJECTION_ASSIGNMENT_TOKEN_RE,
    _CMD_INJECTION_DOLLAR_BRACE_PREFIX_RE,
    _CMD_INJECTION_DOLLAR_BRACE_TERMINATOR_RE,
    _CMD_INJECTION_DOLLAR_PAREN_PREFIX_RE,
    _CMD_INJECTION_DOLLAR_PAREN_TERMINATOR_RE,
    _CMD_INJECTION_DOLLAR_SUBSTITUTION_RE,
    _CMD_INJECTION_NEWLINE_SHELL_DASH_C_COMPILED_RE,
    _DESERIALIZATION_PICKLE_GLOBAL_GENERIC_COMPILED_RE,
    _FILE_UPLOAD_ATTR_EQUALS_WHITESPACE_RE,
    _FILE_UPLOAD_BENIGN_TERMINAL_ALTERNATION,
    _FILE_UPLOAD_BENIGN_TERMINAL_EXTENSIONS,
    _FILE_UPLOAD_DANGEROUS_EXT_ALTERNATION,
    _FILE_UPLOAD_DANGEROUS_EXTENSIONS,
    _FILE_UPLOAD_DECODED_TRUNCATION_RE,
    _FILE_UPLOAD_DOUBLE_EXT_ALTERNATION,
    _FILE_UPLOAD_DOUBLE_EXT_EXTENSIONS,
    _FILE_UPLOAD_DOUBLE_EXT_PREFIX_RE,
    _FILE_UPLOAD_DOUBLE_EXTENSION_RE,
    _FILE_UPLOAD_FILENAME_EQUALS_RE,
    _FILE_UPLOAD_NULL_OR_SEPARATOR_TRUNCATION_RE,
    _FILE_UPLOAD_QUOTE_RE,
    _FILE_UPLOAD_TRUNCATION_RE,
    _HTML_TAG_OPEN_RE,
    _LOAD_FILE_SCAN_PREFIX_RE,
    _LOAD_FILE_SCAN_TERMINATOR_RE,
    _PICKLE_GLOBAL_DOTTED_SEGMENTS_MAX,
    _PICKLE_GLOBAL_IDENT_FULL_RE,
    _PICKLE_GLOBAL_IDENT_MAX_LEN,
    _PICKLE_GLOBAL_IDENT_START_RE,
    _PICKLE_GLOBAL_NEWLINE_RE,
    _PICKLE_GLOBAL_NON_MODULE_CHAR_RE,
    _QUOTE_SPLICE_QUOTE_RUN_RE,
    _QUOTE_SPLICE_WORD_CHAR_RE,
    _SQLI_LOAD_FILE_RE,
    _TEMPLATE_ASP_KEYWORD_RE,
    _TEMPLATE_ASP_PREFIX_RE,
    _TEMPLATE_ASP_TERMINATOR_RE,
    _TEMPLATE_CURLY_CALL_RE,
    _TEMPLATE_CURLY_KEYWORD_RE,
    _TEMPLATE_CURLY_PREFIX_RE,
    _TEMPLATE_CURLY_TERMINATOR_RE,
    _TEMPLATE_DOLLAR_BRACE_CALL_RE,
    _TEMPLATE_DOLLAR_BRACE_PREFIX_RE,
    _TEMPLATE_DOLLAR_BRACE_TERMINATOR_RE,
    _TEMPLATE_PERCENT_KEYWORD_RE,
    _TEMPLATE_PERCENT_PREFIX_RE,
    _TEMPLATE_PERCENT_TERMINATOR_RE,
    _brace_expansion_is_dangerous_command,
    _cmd_injection_dollar_scan_matches,
    _cmd_injection_shell_dash_c_finditer,
    _file_upload_double_extension_scan_matches,
    _file_upload_scan_window,
    _ldap_null_byte_attr_finditer,
    _ldap_null_byte_attr_name_start,
    _ldap_null_byte_value_start,
    _load_file_scan_matches,
    _pickle_global_chain_start,
    _pickle_global_first_valid_marker,
    _pickle_global_generic_finditer,
    _pickle_global_run_start,
    _quote_splice_finditer,
    _quote_splice_word_start,
    _template_asp_keyword_scan_matches,
    _template_curly_call_scan_matches,
    _template_curly_keyword_scan_matches,
    _template_dollar_brace_scan_matches,
    _template_hash_brace_scan_matches,
    _template_percent_keyword_scan_matches,
)
from guard_core.handlers._suspatterns_pattern_table import (
    _PATTERN_DEFINITIONS,
    DETECTION_RECON_RAW_VIEW_PATTERN_SOURCES,
)
from guard_core.handlers._suspatterns_pickle import (
    _PICKLE_REDUCE_OR_BUILD_KEYS,
    _PICKLE_SURROGATEESCAPE_HIGH,
    _PICKLE_SURROGATEESCAPE_LOW,
    _pickle_global_candidate_is_injection,
    _pickle_global_prefix_is_opcode_stream,
    _pickle_global_suffix_reaches_reduce_or_build,
    _pickle_opcode_scan_window,
    _pickle_prefix_bounded_read,
    _pickle_prefix_bounded_readinto,
    _pickle_prefix_bounded_readline,
    _pickle_prefix_load_frame,
    _pickle_prefix_walk_from_start,
    _pickle_prefix_window_from_chars,
    _pickle_suffix_walk_reaches_reduce_or_build,
    _PickleOpcodePrefixResolutionBlocked,
    _PickleOpcodePrefixShortRead,
    _PickleOpcodePrefixUnpickler,
)
from guard_core.handlers._suspatterns_regex import (
    _CANDIDATE_REJECTION_VALIDATORS,
    _DECODE_BUDGET_EXHAUSTED_PATTERN,
    _WINDOWED_PATTERN_FINDERS,
    DETECTION_CATEGORY_WEIGHTS,
    DETECTION_PATTERN_WEIGHT_OVERRIDES,
    _build_regex_threat,
    _build_timeout_threat,
    _decode_budget_exhausted_threat,
    _first_accepted_regex_threat,
    _pattern_excluded_from_view,
    _pattern_should_be_skipped,
    _resolve_pattern_weight,
    _sanitize_for_reporting,
)
from guard_core.handlers._suspatterns_scan_windows import (
    _SCAN_WINDOW_BOUND_SOURCES,
    _SCAN_WINDOW_PATTERNS,
    _iter_scan_window_matches,
)
from guard_core.handlers._suspatterns_shell_sources import (
    _AMBIGUOUS_BACKTICK_INJECTION_CONTEXTS,
    _BACKTICK_WINDOW_DELIMITER_CHARS,
    _BACKTICK_WINDOW_DELIMITER_RE,
    _BARE_SHELL_PARAMETER_NAME_RE,
    _BRACE_EXPANSION_COMMAND_RE,
    _BRACE_EXPANSION_ITEM_RE,
    _CTX_CMD_INJECTION_WITH_URL_PATH,
    _CTX_LOG4SHELL,
    _GLOB_WILDCARD_ATOM_RE,
    _GLOB_WILDCARD_CHAR_RE,
    _GLOB_WILDCARD_PATH_RUN_RE,
    _GLUED_BACKTICK_ASCII_WORD_RE,
    _GLUED_BACKTICK_CANDIDATE_RE,
    _GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE,
    _IMPLAUSIBLE_DOLLAR_PAREN_TOKEN_CHARS_RE,
    _IMPLAUSIBLE_SQL_IDENTIFIER_CHARS_RE,
    _PATTERN_SCAN_WINDOW_MATCHERS,
    _PY_DANGEROUS_METHOD_RE,
    _PY_DANGEROUS_MODULE_RE,
    _PY_GETATTR_INDIRECTION_RE,
    _PY_VARS_INDIRECTION_RE,
    _QUOTE_SPLICE_CANDIDATE_COMPILED_RE,
    _QUOTE_SPLICE_CANDIDATE_RE,
    _SHELL_CHAIN_OPERATOR_RE,
    _SHELL_SPECIAL_PARAMETER_NAMES,
    _STRONG_SQL_KEYWORD_GLUED_PREFIX_RE,
    _STRONG_SQL_KEYWORD_GLUED_SUFFIX_RE,
    DETECTION_RAW_VIEW_PATTERN_SOURCES,
    DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES,
    _glob_wildcard_scan_matches,
)
from guard_core.handlers._suspatterns_shell_validators import (
    _GLOB_WILDCARD_COMMAND_BOUNDARY_PREFIX_RE,
    _GLOB_WILDCARD_COMMAND_SUFFIX_CHARS,
    _GLOB_WILDCARD_LETTER_RE,
    _GLOB_WILDCARD_VALUE_START_CONTEXTS,
    _SHELL_METACHARACTER_WINDOW_RE,
    _SHELL_TEXT_PRINTABLE_ASCII_RE,
    _backtick_pair_context_window,
    _backtick_pair_glued,
    _backtick_token_has_chained_shell_operators,
    _backtick_token_is_implausible_sql_identifier,
    _backtick_window_end,
    _backtick_window_start,
    _dollar_substitution_pair_backtick_quoted,
    _dollar_substitution_pair_is_injection,
    _dollar_substitution_token_is_implausible,
    _glob_wildcard_token_is_dangerous_command,
    _glob_wildcard_token_is_word_shaped,
    _glued_backtick_pair_is_injection,
    _quote_splice_token_is_dangerous_command,
    _strong_sql_keyword_glued_to_pair,
)
from guard_core.handlers._suspatterns_sources import (
    _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE,
    _CMD_INJECTION_NODE_CHILD_PROCESS_RE,
    _CMD_INJECTION_PHP_ASSERT_VARIABLE_RE,
    _CMD_INJECTION_PYTHON_EXEC_FAMILY_RE,
    _CMD_INJECTION_SHELL_DASH_FLAG_RE,
    _CTX_ALL,
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
    _CTX_SSRF,
    _CTX_TEMPLATE,
    _CTX_XML,
    _CTX_XSS,
    _DEFAULT_COMPILER_TIMEOUT,
    _DEFAULT_MAX_BODY_INSPECT_BYTES,
    _DEFAULT_MAX_SCAN_LENGTH,
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
    _ENHANCED_CONFIG_REQUIRED_ATTRS,
    _FILE_INCLUSION_BARE_HOST_RE,
    _FILE_INCLUSION_HOST_LABEL_RE,
    _FILE_INCLUSION_JSON_VALUE_RE,
    _HTTP_SPLIT_CRLF_RE,
    _JS_DYNAMIC_EVAL_BRACKET_RE,
    _JS_DYNAMIC_EVAL_CTOR_GADGET_RE,
    _JS_DYNAMIC_EVAL_FUNCTION_CTOR_RE,
    _JS_DYNAMIC_EVAL_TIMER_STRING_ARG_RE,
    _LDAP_ATTR_DESC_RE,
    _LDAP_ATTR_EXTENSIBLE_MATCH_RE,
    _LDAP_BREAKOUT_ATTACK_TOKEN_RE,
    _LDAP_BREAKOUT_BACKWARD_BOUNDARY_CHARS,
    _LDAP_BREAKOUT_FORWARD_BOUNDARY_CHARS,
    _LDAP_BREAKOUT_LOCAL_SCAN_CHARS,
    _LDAP_BREAKOUT_WILDCARD_CLAUSE_END_RE,
    _LDAP_FILTER_EXPRESSION_STRUCTURE_RE,
    _LDAP_NULL_BYTE_ATTR_COMPILED_RE,
    _LDAP_NULL_BYTE_ATTR_CONTINUATION_CHAR_RE,
    _LDAP_NULL_BYTE_ATTR_LEAD_CHAR_RE,
    _LDAP_NULL_BYTE_ATTR_RE,
    _LDAP_NULL_BYTE_BARE_RE,
    _LDAP_NULL_BYTE_DECODED_ATTR_COMPILED_RE,
    _LDAP_NULL_BYTE_DECODED_ATTR_RE,
    _LDAP_NULL_BYTE_DECODED_BARE_RE,
    _LDAP_NULL_BYTE_DECODED_TAIL_RE,
    _LDAP_NULL_BYTE_TAIL_RE,
    _LDAP_NULL_BYTE_VALUE_CHAR_RE,
    _LDAP_PAREN_BREAKOUT_RE,
    _LDAP_PAREN_CONJUNCTION_FOLLOWUP_ATTR_RE,
    _LDAP_PAREN_CONJUNCTION_FOLLOWUP_SYMBOL_RE,
    _LDAP_PAREN_CONJUNCTION_RE,
    _LDAP_WILDCARD_CHAIN_RE,
    _LDAP_WILDCARD_EQUALS_RE,
    _PATH_ONLY_CHAR_RE,
    _PATH_ONLY_PREFIX_RE,
    _PATH_ONLY_SEP_RE,
    _PATH_ONLY_SUFFIX_RE,
    _PATH_TRAVERSAL_DECODED_SHAPE_RE,
    _PATH_TRAVERSAL_ENCODED_DOT_RE,
    _PATH_TRAVERSAL_SEMICOLON_SEP_RE,
    _PICKLE_DOTTED_MODULE_RE,
    _PICKLE_IDENT_RE,
    _PICKLE_OPCODE_WORK_BUDGET_BYTES,
    _PROTO_POLLUTION_PROTOTYPE_ASSIGN_RE,
    _PROTO_POLLUTION_SET_PROTOTYPE_OF_RE,
    _SELECT_FROM_RE,
    _SELECT_STAR_RE,
    _SINGLE_LINE_PREFIX_RE,
    _SINGLE_LINE_SUFFIX_RE,
    _SQLI_COMMENT_TERMINATOR_RE,
    _SQLI_ORDER_BY_TERMINATOR_RE,
    _SQLI_TAUTOLOGY_RE,
    _SSRF_BARE_METADATA_ALIAS_RE,
    _SSTI_HASH_BRACE_SHAPE_RE,
    _TERMINAL_PATH_SUFFIX_RE,
    _TOP_LEVEL_PATH_PREFIX_RE,
    _WHERE_CLAUSE_RE,
    _XML_XXE_PUBLIC_EXTERNAL_DTD_RE,
    _XSS_JS_SCHEME_CTRL_CHAR_RE,
    ALL_DETECTION_CATEGORIES,
    CATEGORY_CONTEXT_MAP,
    _nested_path_pattern,
    _path_only_pattern,
    _regex_anomaly,
    _supports_enhanced_config,
)
from guard_core.handlers._suspatterns_state import (
    _HTML_EVENT_HANDLER_ALTERNATION,
    _HTML_EVENT_HANDLER_ATTRS,
    _HTML_EVENT_HANDLER_ATTRS_PROVENANCE,
    _LEGACY_DETECTION_STATE,
    _build_enhanced_detection_state,
    _DetectionState,
)
from guard_core.handlers._suspatterns_views import _SusPatternsViewsMixin
from guard_core.handlers._suspatterns_xml_xxe import (
    _XML_XXE_CLASS3_BOUNDARY_RE,
    _XML_XXE_CLASS12_BOUNDARY_RE,
    _XML_XXE_DOCTYPE_RE,
    _XML_XXE_PUBLIC_EXTERNAL_DTD_COMPILED_RE,
    _XML_XXE_PUBLIC_RE,
    _XML_XXE_QUOTE_CHARS,
    _XML_XXE_SCHEME_RE,
    _XML_XXE_W3_ORG_RE,
    _xml_xxe_candidate_span,
    _xml_xxe_first_at_or_after,
    _xml_xxe_precompute,
    _xml_xxe_public_external_dtd_finditer,
    _xml_xxe_public_run_bounds,
    _xml_xxe_scheme_completion_end,
    _xml_xxe_valid_quote_completions,
)

logger = logging.getLogger("guard_core.handlers.suspatterns")

_LEGACY_DETECTION_WARNING = (
    "Detection is running without a SecurityConfig (legacy mode): pass a "
    "SecurityConfig so the preprocessor and the configured pattern set "
    "apply; running unconfigured is deprecated and will be removed in a "
    "future major release."
)

_legacy_detection_warned = False


def _warn_if_legacy_detection(compiler: PatternCompiler | None) -> None:
    global _legacy_detection_warned
    if compiler is not None or _legacy_detection_warned:
        return
    _legacy_detection_warned = True
    warnings.warn(_LEGACY_DETECTION_WARNING, DeprecationWarning, stacklevel=3)
    logger.warning(_LEGACY_DETECTION_WARNING)


__all__ = [
    "ALL_DETECTION_CATEGORIES",
    "ALWAYS_SCAN_HEADER_PATTERNS",
    "CATEGORY_CONTEXT_MAP",
    "DETECTION_CATEGORY_WEIGHTS",
    "DETECTION_PATTERN_WEIGHT_OVERRIDES",
    "DETECTION_RAW_VIEW_PATTERN_SOURCES",
    "DETECTION_RECON_RAW_VIEW_PATTERN_SOURCES",
    "DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES",
    "SusPatternsManager",
    "_AMBIGUOUS_BACKTICK_INJECTION_CONTEXTS",
    "_ATTR_EQUALS_WHITESPACE_RE",
    "_BACKTICK_WINDOW_DELIMITER_CHARS",
    "_BACKTICK_WINDOW_DELIMITER_RE",
    "_BARE_SHELL_PARAMETER_NAME_RE",
    "_BRACE_EXPANSION_COMMAND_RE",
    "_BRACE_EXPANSION_ITEM_RE",
    "_BRACE_EXPANSION_LETTER_RE",
    "_BRACE_EXPANSION_WORD_ITEM_RE",
    "_BUILTIN_PATTERN_COMPILE_FLAGS",
    "_CANDIDATE_REJECTION_VALIDATORS",
    "_CMD_INJECTION_ASSIGNMENT_PREFIX_RE",
    "_CMD_INJECTION_ASSIGNMENT_TOKEN_RE",
    "_CMD_INJECTION_DOLLAR_BRACE_PREFIX_RE",
    "_CMD_INJECTION_DOLLAR_BRACE_TERMINATOR_RE",
    "_CMD_INJECTION_DOLLAR_PAREN_PREFIX_RE",
    "_CMD_INJECTION_DOLLAR_PAREN_TERMINATOR_RE",
    "_CMD_INJECTION_DOLLAR_SUBSTITUTION_RE",
    "_CMD_INJECTION_NEWLINE_SHELL_DASH_C_COMPILED_RE",
    "_CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE",
    "_CMD_INJECTION_NODE_CHILD_PROCESS_RE",
    "_CMD_INJECTION_PHP_ASSERT_VARIABLE_RE",
    "_CMD_INJECTION_PYTHON_EXEC_FAMILY_RE",
    "_CMD_INJECTION_SHELL_DASH_FLAG_RE",
    "_CTX_ALL",
    "_CTX_CMD_INJECTION",
    "_CTX_CMD_INJECTION_WITH_URL_PATH",
    "_CTX_CMS_PROBING",
    "_CTX_CODE_INJECTION",
    "_CTX_DESERIALIZATION",
    "_CTX_DIR_TRAVERSAL",
    "_CTX_FILE_INCLUSION",
    "_CTX_FILE_UPLOAD",
    "_CTX_HTTP_SPLIT",
    "_CTX_LDAP",
    "_CTX_LOG4SHELL",
    "_CTX_NOSQL",
    "_CTX_PATH_TRAVERSAL",
    "_CTX_PROTO_POLLUTION",
    "_CTX_RECON",
    "_CTX_SENSITIVE_FILE",
    "_CTX_SQLI",
    "_CTX_SSRF",
    "_CTX_TEMPLATE",
    "_CTX_XML",
    "_CTX_XSS",
    "_DECODE_BUDGET_EXHAUSTED_PATTERN",
    "_DEFAULT_COMPILER_TIMEOUT",
    "_DEFAULT_MAX_BODY_INSPECT_BYTES",
    "_DEFAULT_MAX_SCAN_LENGTH",
    "_DESERIALIZATION_DOTNET_B64_RE",
    "_DESERIALIZATION_JAVA_B64_RE",
    "_DESERIALIZATION_PICKLE_B64_RE",
    "_DESERIALIZATION_PICKLE_GLOBAL_GENERIC_COMPILED_RE",
    "_DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE",
    "_DESERIALIZATION_PICKLE_OS_GLOBAL_RE",
    "_DESERIALIZATION_RUBY_B64_RE",
    "_DIR_TRAVERSAL_ETC_SENSITIVE_RE",
    "_DIR_TRAVERSAL_PROC_ENVIRON_RE",
    "_DIR_TRAVERSAL_VAR_LOG_RE",
    "_DIR_TRAVERSAL_WINDOWS_INI_RE",
    "_DetectionState",
    "_ENHANCED_CONFIG_REQUIRED_ATTRS",
    "_FILE_INCLUSION_BARE_HOST_RE",
    "_FILE_INCLUSION_HOST_LABEL_RE",
    "_FILE_INCLUSION_JSON_VALUE_RE",
    "_FILE_UPLOAD_ATTR_EQUALS_WHITESPACE_RE",
    "_FILE_UPLOAD_BENIGN_TERMINAL_ALTERNATION",
    "_FILE_UPLOAD_BENIGN_TERMINAL_EXTENSIONS",
    "_FILE_UPLOAD_DANGEROUS_EXTENSIONS",
    "_FILE_UPLOAD_DANGEROUS_EXT_ALTERNATION",
    "_FILE_UPLOAD_DECODED_TRUNCATION_RE",
    "_FILE_UPLOAD_DOUBLE_EXTENSION_RE",
    "_FILE_UPLOAD_DOUBLE_EXT_ALTERNATION",
    "_FILE_UPLOAD_DOUBLE_EXT_EXTENSIONS",
    "_FILE_UPLOAD_DOUBLE_EXT_PREFIX_RE",
    "_FILE_UPLOAD_FILENAME_EQUALS_RE",
    "_FILE_UPLOAD_NULL_OR_SEPARATOR_TRUNCATION_RE",
    "_FILE_UPLOAD_QUOTE_RE",
    "_FILE_UPLOAD_TRUNCATION_RE",
    "_GLOB_WILDCARD_ATOM_RE",
    "_GLOB_WILDCARD_CHAR_RE",
    "_GLOB_WILDCARD_COMMAND_BOUNDARY_PREFIX_RE",
    "_GLOB_WILDCARD_COMMAND_SUFFIX_CHARS",
    "_GLOB_WILDCARD_LETTER_RE",
    "_GLOB_WILDCARD_PATH_RUN_RE",
    "_GLOB_WILDCARD_VALUE_START_CONTEXTS",
    "_GLUED_BACKTICK_ASCII_WORD_RE",
    "_GLUED_BACKTICK_CANDIDATE_RE",
    "_GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE",
    "_HTML_EVENT_HANDLER_ALTERNATION",
    "_HTML_EVENT_HANDLER_ATTRS",
    "_HTML_EVENT_HANDLER_ATTRS_PROVENANCE",
    "_HTML_TAG_OPEN_RE",
    "_HTTP_SPLIT_CRLF_RE",
    "_IMPLAUSIBLE_DOLLAR_PAREN_TOKEN_CHARS_RE",
    "_IMPLAUSIBLE_SQL_IDENTIFIER_CHARS_RE",
    "_JS_DYNAMIC_EVAL_BRACKET_RE",
    "_JS_DYNAMIC_EVAL_CTOR_GADGET_RE",
    "_JS_DYNAMIC_EVAL_FUNCTION_CTOR_RE",
    "_JS_DYNAMIC_EVAL_TIMER_STRING_ARG_RE",
    "_LDAP_ATTR_DESC_RE",
    "_LDAP_ATTR_EXTENSIBLE_MATCH_RE",
    "_LDAP_BREAKOUT_ATTACK_TOKEN_RE",
    "_LDAP_BREAKOUT_BACKWARD_BOUNDARY_CHARS",
    "_LDAP_BREAKOUT_FORWARD_BOUNDARY_CHARS",
    "_LDAP_BREAKOUT_LOCAL_SCAN_CHARS",
    "_LDAP_BREAKOUT_WILDCARD_CLAUSE_END_RE",
    "_LDAP_FILTER_EXPRESSION_STRUCTURE_RE",
    "_LDAP_NULL_BYTE_ATTR_COMPILED_RE",
    "_LDAP_NULL_BYTE_ATTR_CONTINUATION_CHAR_RE",
    "_LDAP_NULL_BYTE_ATTR_LEAD_CHAR_RE",
    "_LDAP_NULL_BYTE_ATTR_RE",
    "_LDAP_NULL_BYTE_BARE_RE",
    "_LDAP_NULL_BYTE_DECODED_ATTR_COMPILED_RE",
    "_LDAP_NULL_BYTE_DECODED_ATTR_RE",
    "_LDAP_NULL_BYTE_DECODED_BARE_RE",
    "_LDAP_NULL_BYTE_DECODED_TAIL_RE",
    "_LDAP_NULL_BYTE_TAIL_RE",
    "_LDAP_NULL_BYTE_VALUE_CHAR_RE",
    "_LDAP_PAREN_BREAKOUT_RE",
    "_LDAP_PAREN_CONJUNCTION_FOLLOWUP_ATTR_RE",
    "_LDAP_PAREN_CONJUNCTION_FOLLOWUP_SYMBOL_RE",
    "_LDAP_PAREN_CONJUNCTION_RE",
    "_LDAP_WILDCARD_CHAIN_RE",
    "_LDAP_WILDCARD_EQUALS_RE",
    "_LEGACY_DETECTION_STATE",
    "_LEGACY_IPV4_BLOCKED_NETWORKS",
    "_LEGACY_IPV4_HOST_RE",
    "_LEGACY_IPV4_PART_RE",
    "_LOAD_FILE_SCAN_PREFIX_RE",
    "_LOAD_FILE_SCAN_TERMINATOR_RE",
    "_LOG4SHELL_JNDI_LOOKUP_RE",
    "_MIN_BARE_DECIMAL_LEGACY_IPV4",
    "_PATH_ONLY_CHAR_RE",
    "_PATH_ONLY_PREFIX_RE",
    "_PATH_ONLY_SEP_RE",
    "_PATH_ONLY_SUFFIX_RE",
    "_PATH_TRAVERSAL_DECODED_SHAPE_RE",
    "_PATH_TRAVERSAL_ENCODED_DOT_RE",
    "_PATH_TRAVERSAL_SEMICOLON_SEP_RE",
    "_PATTERN_SCAN_WINDOW_MATCHERS",
    "_PICKLE_DOTTED_MODULE_RE",
    "_PICKLE_GLOBAL_DOTTED_SEGMENTS_MAX",
    "_PICKLE_GLOBAL_IDENT_FULL_RE",
    "_PICKLE_GLOBAL_IDENT_MAX_LEN",
    "_PICKLE_GLOBAL_IDENT_START_RE",
    "_PICKLE_GLOBAL_NEWLINE_RE",
    "_PICKLE_GLOBAL_NON_MODULE_CHAR_RE",
    "_PICKLE_IDENT_RE",
    "_PICKLE_OPCODE_WORK_BUDGET_BYTES",
    "_PICKLE_REDUCE_OR_BUILD_KEYS",
    "_PICKLE_SURROGATEESCAPE_HIGH",
    "_PICKLE_SURROGATEESCAPE_LOW",
    "_PROTO_POLLUTION_PROTOTYPE_ASSIGN_RE",
    "_PROTO_POLLUTION_SET_PROTOTYPE_OF_RE",
    "_PY_DANGEROUS_METHOD_RE",
    "_PY_DANGEROUS_MODULE_RE",
    "_PY_GETATTR_INDIRECTION_RE",
    "_PY_VARS_INDIRECTION_RE",
    "_PickleOpcodePrefixResolutionBlocked",
    "_PickleOpcodePrefixShortRead",
    "_PickleOpcodePrefixUnpickler",
    "_QUOTE_SPLICE_CANDIDATE_COMPILED_RE",
    "_QUOTE_SPLICE_CANDIDATE_RE",
    "_QUOTE_SPLICE_QUOTE_RUN_RE",
    "_QUOTE_SPLICE_WORD_CHAR_RE",
    "_SCAN_WINDOW_BOUND_SOURCES",
    "_SCAN_WINDOW_PATTERNS",
    "_SELECT_FROM_RE",
    "_SELECT_STAR_RE",
    "_SHELL_CHAIN_OPERATOR_RE",
    "_SHELL_METACHARACTER_WINDOW_RE",
    "_SHELL_SPECIAL_PARAMETER_NAMES",
    "_SHELL_TEXT_PRINTABLE_ASCII_RE",
    "_SINGLE_LINE_PREFIX_RE",
    "_SINGLE_LINE_SUFFIX_RE",
    "_SQLI_COMMENT_TERMINATOR_RE",
    "_SQLI_LOAD_FILE_RE",
    "_SQLI_ORDER_BY_TERMINATOR_RE",
    "_SQLI_TAUTOLOGY_RE",
    "_SSRF_BARE_METADATA_ALIAS_RE",
    "_SSTI_HASH_BRACE_SHAPE_RE",
    "_STRONG_SQL_KEYWORD_GLUED_PREFIX_RE",
    "_STRONG_SQL_KEYWORD_GLUED_SUFFIX_RE",
    "_TEMPLATE_ASP_KEYWORD_RE",
    "_TEMPLATE_ASP_PREFIX_RE",
    "_TEMPLATE_ASP_TERMINATOR_RE",
    "_TEMPLATE_CURLY_CALL_RE",
    "_TEMPLATE_CURLY_KEYWORD_RE",
    "_TEMPLATE_CURLY_PREFIX_RE",
    "_TEMPLATE_CURLY_TERMINATOR_RE",
    "_TEMPLATE_DOLLAR_BRACE_CALL_RE",
    "_TEMPLATE_DOLLAR_BRACE_PREFIX_RE",
    "_TEMPLATE_DOLLAR_BRACE_TERMINATOR_RE",
    "_TEMPLATE_PERCENT_KEYWORD_RE",
    "_TEMPLATE_PERCENT_PREFIX_RE",
    "_TEMPLATE_PERCENT_TERMINATOR_RE",
    "_TERMINAL_PATH_SUFFIX_RE",
    "_TOP_LEVEL_PATH_PREFIX_RE",
    "_WHERE_CLAUSE_RE",
    "_WINDOWED_PATTERN_FINDERS",
    "_XML_XXE_CLASS12_BOUNDARY_RE",
    "_XML_XXE_CLASS3_BOUNDARY_RE",
    "_XML_XXE_DOCTYPE_RE",
    "_XML_XXE_PUBLIC_EXTERNAL_DTD_COMPILED_RE",
    "_XML_XXE_PUBLIC_EXTERNAL_DTD_RE",
    "_XML_XXE_PUBLIC_RE",
    "_XML_XXE_QUOTE_CHARS",
    "_XML_XXE_SCHEME_RE",
    "_XML_XXE_W3_ORG_RE",
    "_XSS_JS_SCHEME_CTRL_CHAR_RE",
    "_backtick_pair_context_window",
    "_backtick_pair_glued",
    "_backtick_token_has_chained_shell_operators",
    "_backtick_token_is_implausible_sql_identifier",
    "_backtick_window_end",
    "_backtick_window_start",
    "_brace_expansion_is_dangerous_command",
    "_build_enhanced_detection_state",
    "_build_regex_threat",
    "_build_timeout_threat",
    "_cmd_injection_dollar_scan_matches",
    "_cmd_injection_shell_dash_c_finditer",
    "_decode_budget_exhausted_threat",
    "_decode_legacy_ipv4_host",
    "_decode_legacy_ipv4_part",
    "_dollar_substitution_pair_backtick_quoted",
    "_dollar_substitution_pair_is_injection",
    "_dollar_substitution_token_is_implausible",
    "_file_upload_double_extension_scan_matches",
    "_file_upload_scan_window",
    "_first_accepted_regex_threat",
    "_glob_wildcard_scan_matches",
    "_glob_wildcard_token_is_dangerous_command",
    "_glob_wildcard_token_is_word_shaped",
    "_glued_backtick_pair_is_injection",
    "_is_ambiguous_bare_decimal_port",
    "_is_bare_decimal_legacy_ipv4_part",
    "_is_blocked_legacy_ipv4",
    "_iter_scan_window_matches",
    "_ldap_breakout_backward_window",
    "_ldap_breakout_forward_window",
    "_ldap_filter_expression_forward_extent",
    "_ldap_next_candidate_scan_limit",
    "_ldap_null_byte_attr_finditer",
    "_ldap_null_byte_attr_name_start",
    "_ldap_null_byte_value_start",
    "_ldap_paren_conjunction_is_injection",
    "_ldap_wildcard_chain_is_injection",
    "_legacy_ipv4_match_is_blocked",
    "_load_file_scan_matches",
    "_nested_path_pattern",
    "_path_only_pattern",
    "_pattern_excluded_from_view",
    "_pattern_should_be_skipped",
    "_pickle_global_candidate_is_injection",
    "_pickle_global_chain_start",
    "_pickle_global_first_valid_marker",
    "_pickle_global_generic_finditer",
    "_pickle_global_prefix_is_opcode_stream",
    "_pickle_global_run_start",
    "_pickle_global_suffix_reaches_reduce_or_build",
    "_pickle_opcode_scan_window",
    "_pickle_prefix_bounded_read",
    "_pickle_prefix_bounded_readinto",
    "_pickle_prefix_bounded_readline",
    "_pickle_prefix_load_frame",
    "_pickle_prefix_walk_from_start",
    "_pickle_prefix_window_from_chars",
    "_pickle_suffix_walk_reaches_reduce_or_build",
    "_quote_splice_finditer",
    "_quote_splice_token_is_dangerous_command",
    "_quote_splice_word_start",
    "_regex_anomaly",
    "_resolve_pattern_weight",
    "_sanitize_for_reporting",
    "_strong_sql_keyword_glued_to_pair",
    "_supports_enhanced_config",
    "_template_asp_keyword_scan_matches",
    "_template_curly_call_scan_matches",
    "_template_curly_keyword_scan_matches",
    "_template_dollar_brace_scan_matches",
    "_template_hash_brace_scan_matches",
    "_template_percent_keyword_scan_matches",
    "_xml_xxe_candidate_span",
    "_xml_xxe_first_at_or_after",
    "_xml_xxe_precompute",
    "_xml_xxe_public_external_dtd_finditer",
    "_xml_xxe_public_run_bounds",
    "_xml_xxe_scheme_completion_end",
    "_xml_xxe_valid_quote_completions",
    "logger",
    "sus_patterns_handler",
]


SEMANTIC_ATTACK_TYPE_TO_CATEGORY: dict[str, str] = {
    "xss": "xss",
    "sql": "sqli",
    "command": "cmd_injection",
    "path": "path_traversal",
    "template": "template",
    "suspicious": "custom",
}


def _collect_threat_categories(threats: list[dict[str, Any]]) -> list[str]:
    from guard_core._utils.detection_result_builders import _threat_category

    categories: list[str] = []
    for threat in threats:
        category = _threat_category(threat)
        if category is None:
            continue
        if threat.get("type") == "semantic":
            category = SEMANTIC_ATTACK_TYPE_TO_CATEGORY.get(category, category)
        if category not in categories:
            categories.append(category)
    return categories


def _drop_view_duplicate_threats(
    seen_threats: list[dict[str, Any]],
    new_threats: list[dict[str, Any]],
    new_matched: list[str],
) -> tuple[list[dict[str, Any]], list[str]]:
    # Threats and matched patterns are parallel lists (one append per match), so
    # a raw-view sighting of a pattern over text the processed views already
    # matched is the same evidence and must not inflate the threat score.
    seen = {(threat.get("pattern"), threat.get("match")) for threat in seen_threats}
    kept_threats: list[dict[str, Any]] = []
    kept_matched: list[str] = []
    for threat, pattern in zip(new_threats, new_matched, strict=True):
        key = (threat.get("pattern"), threat.get("match"))
        if key in seen:
            continue
        seen.add(key)
        kept_threats.append(threat)
        kept_matched.append(pattern)
    return kept_threats, kept_matched


def _merge_raw_view_results(
    threats: list[dict[str, Any]],
    matched_patterns: list[str],
    timeouts: list[str],
    raw_results: tuple[list[dict[str, Any]], list[str], list[str]],
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    # The raw view rescans rows that already ran on the processed views, so a
    # row matching both views on the same text must be reported once.
    raw_threats, raw_matched, raw_timeouts = raw_results
    raw_threats, raw_matched = _drop_view_duplicate_threats(
        threats, raw_threats, raw_matched
    )
    return (
        threats + raw_threats,
        matched_patterns + raw_matched,
        timeouts + [t for t in raw_timeouts if t not in timeouts],
    )


_BUILTIN_PATTERN_COMPILE_FLAGS = re.IGNORECASE


class SusPatternsManager(_SusPatternsViewsMixin):
    _instance = None
    _config = None

    _pattern_definitions: list[tuple[str, frozenset[str], str]] = _PATTERN_DEFINITIONS

    patterns: list[str] = [p[0] for p in _pattern_definitions]

    custom_patterns: set[str]
    compiled_patterns: list[tuple[re.Pattern, frozenset[str], str]]
    compiled_custom_patterns: set[tuple[re.Pattern, frozenset[str], str]]
    redis_handler: Any
    agent_handler: Any
    _detection_state: _DetectionState

    def __new__(
        cls: type["SusPatternsManager"], config: Any = None
    ) -> "SusPatternsManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.custom_patterns = set()
            cls._instance.compiled_patterns = [
                (
                    re.compile(pattern, _BUILTIN_PATTERN_COMPILE_FLAGS),
                    contexts,
                    category,
                )
                for pattern, contexts, category in cls._pattern_definitions
            ]
            cls._instance.compiled_custom_patterns = set()
            cls._instance.redis_handler = None
            cls._instance.agent_handler = None

            cls._config = config

            if _supports_enhanced_config(config):
                cls._instance._detection_state = _build_enhanced_detection_state(config)
            else:
                cls._instance._detection_state = _LEGACY_DETECTION_STATE

        return cls._instance

    @property
    def _compiler(self) -> PatternCompiler | None:
        return self._detection_state.compiler

    @_compiler.setter
    def _compiler(self, value: PatternCompiler | None) -> None:
        self._detection_state = self._detection_state._replace(compiler=value)

    @property
    def _preprocessor(self) -> ContentPreprocessor | None:
        return self._detection_state.preprocessor

    @_preprocessor.setter
    def _preprocessor(self, value: ContentPreprocessor | None) -> None:
        self._detection_state = self._detection_state._replace(preprocessor=value)

    @property
    def _semantic_analyzer(self) -> SemanticAnalyzer | None:
        return self._detection_state.semantic_analyzer

    @_semantic_analyzer.setter
    def _semantic_analyzer(self, value: SemanticAnalyzer | None) -> None:
        self._detection_state = self._detection_state._replace(semantic_analyzer=value)

    @property
    def _performance_monitor(self) -> PerformanceMonitor | None:
        return self._detection_state.performance_monitor

    @_performance_monitor.setter
    def _performance_monitor(self, value: PerformanceMonitor | None) -> None:
        self._detection_state = self._detection_state._replace(
            performance_monitor=value
        )

    @property
    def _semantic_threshold(self) -> float:
        return self._detection_state.semantic_threshold

    @_semantic_threshold.setter
    def _semantic_threshold(self, value: float) -> None:
        self._detection_state = self._detection_state._replace(semantic_threshold=value)

    @property
    def _threat_score_threshold(self) -> float:
        return self._detection_state.threat_score_threshold

    @_threat_score_threshold.setter
    def _threat_score_threshold(self, value: float) -> None:
        self._detection_state = self._detection_state._replace(
            threat_score_threshold=value
        )

    async def initialize_agent(self, agent_handler: Any) -> None:
        self.agent_handler = agent_handler

    async def detect(
        self,
        content: str,
        ip_address: str,
        context: str = "unknown",
        correlation_id: str | None = None,
        enabled_categories: set[str] | None = None,
        *,
        content_preview: str | None = None,
    ) -> dict[str, Any]:
        original_content = content
        execution_start = time.monotonic()
        state = self._detection_state
        _warn_if_legacy_detection(state.compiler)

        (
            processed_content,
            decode_budget_exhausted,
            precomputed_decoded,
        ) = await self._preprocess_content(content, correlation_id, state=state)

        regex_threats, matched_patterns, timeouts = await self._check_regex_patterns(
            processed_content,
            ip_address,
            correlation_id,
            context,
            enabled_categories,
            state=state,
            raw_view_only=False if state.preprocessor else None,
        )

        raw_view_results = await self._check_raw_view_patterns(
            content, ip_address, context, correlation_id, enabled_categories, state
        )
        regex_threats, matched_patterns, timeouts = _merge_raw_view_results(
            regex_threats, matched_patterns, timeouts, raw_view_results
        )

        decoded_view_threat = await self._check_decoded_view_path_traversal(
            processed_content, content, context, enabled_categories, state
        )
        if decoded_view_threat:
            regex_threats = regex_threats + [decoded_view_threat]
            matched_patterns = matched_patterns + [decoded_view_threat["pattern"]]

        (
            url_decoded_threats,
            url_decoded_matched,
            url_decoded_timeouts,
            url_decoded_budget_exhausted,
        ) = await self._check_url_decoded_view_patterns(
            content,
            ip_address,
            context,
            correlation_id,
            enabled_categories,
            state,
            precomputed_decoded=precomputed_decoded,
            precomputed_decode_budget_exhausted=decode_budget_exhausted,
        )
        regex_threats = regex_threats + url_decoded_threats
        matched_patterns = matched_patterns + url_decoded_matched
        timeouts = timeouts + url_decoded_timeouts

        if decode_budget_exhausted or url_decoded_budget_exhausted:
            exhaustion_threat = _decode_budget_exhausted_threat()
            regex_threats = regex_threats + [exhaustion_threat]
            matched_patterns = matched_patterns + [exhaustion_threat["pattern"]]

        (
            short_base64_threats,
            short_base64_matched,
            short_base64_timeouts,
        ) = await self._check_short_base64_additive_view_patterns(
            content, ip_address, context, correlation_id, enabled_categories, state
        )
        regex_threats = regex_threats + short_base64_threats
        matched_patterns = matched_patterns + short_base64_matched
        timeouts = timeouts + short_base64_timeouts

        semantic_threats: list[dict] = []
        if not _context_header_is_semantic_excluded(context):
            semantic_threats, _semantic_score = await self._check_semantic_threats(
                processed_content, state=state, raw_content=original_content
            )

        threats = regex_threats + semantic_threats
        is_threat = (
            _regex_anomaly(regex_threats) >= state.threat_score_threshold
            or len(semantic_threats) > 0
        )

        threat_score = await self._calculate_threat_score(
            regex_threats, semantic_threats
        )

        total_execution_time = time.monotonic() - execution_start

        if state.performance_monitor:
            await state.performance_monitor.record_metric(
                pattern="overall_detection",
                execution_time=total_execution_time,
                content_length=len(content),
                matched=is_threat,
                timeout=False,
                agent_handler=self.agent_handler,
                correlation_id=correlation_id,
            )

        detection_method = "enhanced" if state.compiler else "legacy"

        if is_threat:
            await self._send_threat_event(
                matched_patterns,
                semantic_threats,
                ip_address,
                context,
                content,
                threat_score,
                threats,
                regex_threats,
                timeouts,
                total_execution_time,
                correlation_id,
                detection_method,
                content_preview=content_preview,
            )

        return {
            "is_threat": is_threat,
            "threat_score": threat_score,
            "threats": threats,
            "context": context,
            "original_length": len(original_content),
            "processed_length": len(processed_content),
            "execution_time": total_execution_time,
            "detection_method": detection_method,
            "timeouts": timeouts,
            "correlation_id": correlation_id,
        }

    async def _send_threat_event(
        self,
        matched_patterns: list,
        semantic_threats: list,
        ip_address: str,
        context: str,
        content: str,
        threat_score: float,
        threats: list,
        regex_threats: list,
        timeouts: list,
        execution_time: float,
        correlation_id: str | None,
        detection_method: str | None = None,
        content_preview: str | None = None,
    ) -> None:
        from guard_core._utils.detection_scan import _redact_pattern_source
        from guard_core.core.events.event_types import EVENT_PATTERN_DETECTED

        if detection_method is None:
            detection_method = "enhanced" if self._compiler else "legacy"

        pattern_info = "unknown"
        if matched_patterns:
            pattern_info = matched_patterns[0]
        elif semantic_threats:
            pattern_info = f"semantic:{semantic_threats[0]['attack_type']}"

        preview_source = content_preview if content_preview is not None else content
        capped_preview = (
            preview_source[:100] if len(preview_source) > 100 else preview_source
        )

        threat_categories = _collect_threat_categories(threats)

        pattern_matched = _redact_pattern_source(pattern_info)

        await self._send_pattern_event(
            event_type=EVENT_PATTERN_DETECTED,
            ip_address=ip_address,
            action_taken="threat_detected",
            reason=f"Threat detected in {context}",
            pattern_matched=pattern_matched,
            pattern=pattern_matched,
            context=context,
            content_preview=_sanitize_for_reporting(capped_preview),
            threat_score=threat_score,
            threats=len(threats),
            regex_threats=len(regex_threats),
            semantic_threats=len(semantic_threats),
            timeouts=len(timeouts),
            detection_method=detection_method,
            execution_time_ms=int(execution_time * 1000),
            correlation_id=correlation_id,
            threat_categories=threat_categories,
            category=threat_categories[0] if threat_categories else None,
        )

    async def detect_pattern_match(
        self,
        content: str,
        ip_address: str,
        context: str = "unknown",
        correlation_id: str | None = None,
    ) -> tuple[bool, str | None]:
        from guard_core._utils.detection_scan import _redact_pattern_source

        result = await self.detect(content, ip_address, context, correlation_id)

        if result["is_threat"]:
            if result["threats"]:
                threat = result["threats"][0]
                if threat["type"] == "regex":
                    return True, _redact_pattern_source(threat["pattern"])
                elif threat["type"] == "semantic":
                    return True, f"semantic:{threat.get('attack_type', 'suspicious')}"
            return True, "unknown"

        return False, None


sus_patterns_handler = SusPatternsManager()
