import concurrent.futures
import logging
import re
import time
from collections.abc import Callable, Iterator
from typing import Any

from guard_core.sync._utils.detection_scan import (
    _EVENT_LOOP_SLICE_SECONDS,
    _SCAN_TIME_BUDGET_EXHAUSTED_PATTERN,
    _clamp_to_scan_time_budget,
    _record_scan_time,
    _redact_pattern_source,
    _scan_time_budget_exhausted,
    _scan_time_budget_exhausted_threat,
    _warn_scan_time_cap_reached_once,
)
from guard_core.sync.detection_engine.binary_prefix import (
    build_binary_prefix,
    match_is_binary_dense,
)
from guard_core.sync.detection_engine.compiler import (
    _await_regex_future,
    _yield_to_event_loop,
    report_scan_success,
    report_scan_timeout,
    shared_regex_executor,
)
from guard_core.sync.detection_engine.scan_window import bounded_finditer
from guard_core.sync.handlers._suspatterns_enhanced import _SusPatternsEnhancedMixin
from guard_core.sync.handlers._suspatterns_ldap_ipv4 import (
    _LEGACY_IPV4_HOST_RE,
    _ldap_paren_conjunction_is_injection,
    _ldap_wildcard_chain_is_injection,
    _legacy_ipv4_match_is_blocked,
)
from guard_core.sync.handlers._suspatterns_matchers import (
    _CMD_INJECTION_NEWLINE_SHELL_DASH_C_COMPILED_RE,
    _DESERIALIZATION_PICKLE_GLOBAL_GENERIC_COMPILED_RE,
    _brace_expansion_is_dangerous_command,
    _cmd_injection_shell_dash_c_finditer,
    _ldap_null_byte_attr_finditer,
    _pickle_global_generic_finditer,
    _quote_splice_finditer,
)
from guard_core.sync.handlers._suspatterns_pattern_table import (
    DETECTION_RECON_RAW_VIEW_PATTERN_SOURCES,
    NOISE_PRONE_PATTERN_SOURCES,
    RECON_OPTIONAL_SEPARATOR_PATTERN_SOURCES,
)
from guard_core.sync.handlers._suspatterns_pickle import (
    _pickle_global_candidate_is_injection,
)
from guard_core.sync.handlers._suspatterns_registry import _SusPatternsRegistryMixin
from guard_core.sync.handlers._suspatterns_shell_sources import (
    _BRACE_EXPANSION_COMMAND_RE,
    _GLOB_WILDCARD_ATOM_RE,
    _GLUED_BACKTICK_CANDIDATE_RE,
    _GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE,
    _PATTERN_SCAN_WINDOW_MATCHERS,
    _QUOTE_SPLICE_CANDIDATE_COMPILED_RE,
    _QUOTE_SPLICE_CANDIDATE_RE,
    DETECTION_RAW_VIEW_PATTERN_SOURCES,
    DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES,
)
from guard_core.sync.handlers._suspatterns_shell_validators import (
    _dollar_substitution_pair_is_injection,
    _glob_wildcard_token_is_dangerous_command,
    _glued_backtick_pair_is_injection,
    _quote_splice_token_is_dangerous_command,
)
from guard_core.sync.handlers._suspatterns_sources import (
    _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE,
    _DEFAULT_COMPILER_TIMEOUT,
    _DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE,
    _EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX,
    _LDAP_NULL_BYTE_ATTR_COMPILED_RE,
    _LDAP_NULL_BYTE_ATTR_RE,
    _LDAP_NULL_BYTE_DECODED_ATTR_COMPILED_RE,
    _LDAP_NULL_BYTE_DECODED_ATTR_RE,
    _LDAP_NULL_BYTE_DECODED_TAIL_RE,
    _LDAP_NULL_BYTE_TAIL_RE,
    _LDAP_PAREN_BREAKOUT_RE,
    _LDAP_PAREN_CONJUNCTION_RE,
    _LDAP_WILDCARD_CHAIN_RE,
    _LDAP_WILDCARD_EQUALS_RE,
    _SELECT_FROM_RE,
    _SELECT_STAR_RE,
    _SENSITIVE_SOURCE_EXTENSION_PATH_RE,
    _WHERE_CLAUSE_RE,
    _XML_XXE_PUBLIC_EXTERNAL_DTD_RE,
    ALL_DETECTION_CATEGORIES,
    _recon_path_value_is_probe,
    _source_extension_path_is_probe,
)
from guard_core.sync.handlers._suspatterns_state import _DetectionState
from guard_core.sync.handlers._suspatterns_xml_xxe import (
    _XML_XXE_PUBLIC_EXTERNAL_DTD_COMPILED_RE,
    _xml_internal_entity_finditer,
    _xml_system_finditer,
    _xml_xxe_public_external_dtd_finditer,
)

logger = logging.getLogger("guard_core.sync.handlers.suspatterns")

DETECTION_CATEGORY_WEIGHTS: dict[str, float] = {
    category: 1.0 for category in ALL_DETECTION_CATEGORIES
}

DETECTION_PATTERN_WEIGHT_OVERRIDES: dict[str, float] = {
    _SELECT_FROM_RE: 0.5,
    _SELECT_STAR_RE: 0.5,
    _WHERE_CLAUSE_RE: 0.5,
}


def _resolve_pattern_weight(pattern: str, category: str) -> float:
    if pattern in DETECTION_PATTERN_WEIGHT_OVERRIDES:
        return DETECTION_PATTERN_WEIGHT_OVERRIDES[pattern]
    return DETECTION_CATEGORY_WEIGHTS.get(category, 1.0)


_DECODE_BUDGET_EXHAUSTED_PATTERN = "decode_budget_exhausted"


def _decode_budget_exhausted_threat() -> dict[str, Any]:
    return {
        "type": "regex",
        "pattern": _DECODE_BUDGET_EXHAUSTED_PATTERN,
        "match": _DECODE_BUDGET_EXHAUSTED_PATTERN,
        "position": 0,
        "execution_time": 0.0,
        "category": "custom",
        "weight": _resolve_pattern_weight(_DECODE_BUDGET_EXHAUSTED_PATTERN, "custom"),
    }


def _pattern_excluded_from_view(
    pattern: re.Pattern,
    raw_view_only: bool | None,
    url_decoded_view_only: bool | None = None,
) -> bool:
    is_raw_view_pattern = pattern.pattern in DETECTION_RAW_VIEW_PATTERN_SOURCES
    is_url_decoded_view_pattern = (
        pattern.pattern in DETECTION_URL_DECODED_VIEW_PATTERN_SOURCES
    )
    is_recon_raw_view_pattern = (
        pattern.pattern in DETECTION_RECON_RAW_VIEW_PATTERN_SOURCES
    )
    if raw_view_only is True:
        return is_url_decoded_view_pattern or not (
            is_raw_view_pattern or is_recon_raw_view_pattern
        )
    if url_decoded_view_only is True:
        return is_raw_view_pattern or not is_url_decoded_view_pattern
    if raw_view_only is False:
        return is_raw_view_pattern or is_url_decoded_view_pattern
    return False


def _pattern_should_be_skipped(
    pattern: re.Pattern,
    contexts: frozenset[str],
    category: str,
    *,
    raw_view_only: bool | None,
    skip_filter: bool,
    normalized_context: str,
    enabled_categories: set[str] | None,
    url_decoded_view_only: bool | None = None,
) -> bool:
    if _pattern_excluded_from_view(pattern, raw_view_only, url_decoded_view_only):
        return True
    if not skip_filter and normalized_context not in contexts:
        return True
    return (
        enabled_categories is not None
        and category != "custom"
        and category not in enabled_categories
    )


_CANDIDATE_REJECTION_VALIDATORS: tuple[
    tuple[str, Callable[[re.Match, str], bool]], ...
] = (
    (_LEGACY_IPV4_HOST_RE, lambda m, _c: _legacy_ipv4_match_is_blocked(m)),
    (_LDAP_WILDCARD_CHAIN_RE, lambda m, _c: _ldap_wildcard_chain_is_injection(m)),
    (_LDAP_WILDCARD_EQUALS_RE, lambda m, _c: _ldap_wildcard_chain_is_injection(m)),
    (_LDAP_PAREN_BREAKOUT_RE, lambda m, _c: _ldap_wildcard_chain_is_injection(m)),
    (
        _LDAP_PAREN_CONJUNCTION_RE,
        lambda m, _c: _ldap_paren_conjunction_is_injection(m),
    ),
    (_GLUED_BACKTICK_CANDIDATE_RE, _glued_backtick_pair_is_injection),
    (
        _SENSITIVE_SOURCE_EXTENSION_PATH_RE,
        lambda _m, context: _source_extension_path_is_probe(context),
    ),
    (_GLUED_DOLLAR_SUBSTITUTION_CANDIDATE_RE, _dollar_substitution_pair_is_injection),
    (
        _BRACE_EXPANSION_COMMAND_RE,
        lambda m, _c: _brace_expansion_is_dangerous_command(m),
    ),
    (
        _QUOTE_SPLICE_CANDIDATE_RE,
        lambda m, _c: _quote_splice_token_is_dangerous_command(m),
    ),
    (
        _GLOB_WILDCARD_ATOM_RE,
        _glob_wildcard_token_is_dangerous_command,
    ),
    (_DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE, _pickle_global_candidate_is_injection),
)


_WINDOWED_PATTERN_FINDERS: dict[str, Callable[[str], Iterator[re.Match]]] = {
    _CMD_INJECTION_NEWLINE_SHELL_DASH_C_RE: lambda text: (
        _cmd_injection_shell_dash_c_finditer(
            text, _CMD_INJECTION_NEWLINE_SHELL_DASH_C_COMPILED_RE
        )
    ),
    _LDAP_NULL_BYTE_ATTR_RE: lambda text: _ldap_null_byte_attr_finditer(
        text, _LDAP_NULL_BYTE_ATTR_COMPILED_RE, _LDAP_NULL_BYTE_TAIL_RE
    ),
    _LDAP_NULL_BYTE_DECODED_ATTR_RE: lambda text: _ldap_null_byte_attr_finditer(
        text,
        _LDAP_NULL_BYTE_DECODED_ATTR_COMPILED_RE,
        _LDAP_NULL_BYTE_DECODED_TAIL_RE,
    ),
    _QUOTE_SPLICE_CANDIDATE_RE: lambda text: _quote_splice_finditer(
        text, _QUOTE_SPLICE_CANDIDATE_COMPILED_RE
    ),
    _DESERIALIZATION_PICKLE_GLOBAL_GENERIC_RE: lambda text: (
        _pickle_global_generic_finditer(
            text, _DESERIALIZATION_PICKLE_GLOBAL_GENERIC_COMPILED_RE
        )
    ),
    _XML_XXE_PUBLIC_EXTERNAL_DTD_RE: lambda text: _xml_xxe_public_external_dtd_finditer(
        text, _XML_XXE_PUBLIC_EXTERNAL_DTD_COMPILED_RE
    ),
}

_SCAN_WINDOW_BOUND_SOURCES: dict[str, tuple[tuple[str, str], ...]] = {
    r"<script[^>]*>[^<]*<\/script\s*>": ((r"<script", r"<\/script\s*>"),),
    (
        r"(?:<[A-Za-z/][^<>]*style\s*=\s{0,20}[\"']?[^<>\"']*"
        r"(?:expression|behavior|url)\s*\([^)]*\))"
    ): ((r"<[A-Za-z/][^<>]*style\s*=", r"\)"),),
    r"(?:<object[^>]*>[\s\S]*<\/object\s*>)": ((r"<object", r"<\/object\s*>"),),
    r"(?:<embed[^>]*>[\s\S]*<\/embed\s*>)": ((r"<embed", r"<\/embed\s*>"),),
    r"(?:<applet[^>]*>[\s\S]*<\/applet\s*>)": ((r"<applet", r"<\/applet\s*>"),),
    r"\.\.;[^/\\]*[/\\]": ((r"\.\.;", r"[/\\]"),),
    (
        r"=(?:https?|ftp):\/\/[^\s'\"<>]+\/[^\s'\"<>\/]*"
        r"\.(?:phtml|php[3-5]?|phar|jsp|aspx?|pl|py|txt|inc)(?![a-zA-Z0-9])"
    ): (
        (
            r"=(?:https?|ftp):\/\/",
            r"\.(?:phtml|php\d*|phar|jsp|aspx?|pl|py|txt|inc)[a-zA-Z0-9]*",
        ),
    ),
    r"<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>": ((r"<!(?:ENTITY|DOCTYPE)", r">"),),
    r"(?:<!\[CDATA\[.*?\]\]>)": ((r"<!\[CDATA\[", r"\]\]>"),),
    r"<!DOCTYPE[^>\[]*\[[\s\S]*?<!ENTITY": ((r"<!DOCTYPE", r"<!ENTITY"),),
}

_SCAN_WINDOW_PATTERNS: dict[str, tuple[tuple[re.Pattern, re.Pattern], ...]] = {
    source: tuple(
        (re.compile(prefix, re.IGNORECASE), re.compile(terminator, re.IGNORECASE))
        for prefix, terminator in pairs
    )
    for source, pairs in _SCAN_WINDOW_BOUND_SOURCES.items()
}


def _iter_scan_window_matches(
    content: str,
    pattern: re.Pattern,
    bounds: tuple[tuple[re.Pattern, re.Pattern], ...],
) -> Iterator[re.Match]:
    if pattern.pattern == r"<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>":
        yield from _xml_system_finditer(content)
        return
    if pattern.pattern == r"<!DOCTYPE[^>\[]*\[[\s\S]*?<!ENTITY":
        yield from _xml_internal_entity_finditer(content)
        return
    for prefix, terminator in bounds:
        yield from bounded_finditer(content, pattern, prefix, terminator)


def _sanitize_for_reporting(value: str) -> str:
    return value.encode("utf-8", errors="surrogateescape").decode(
        "utf-8", errors="backslashreplace"
    )


def _build_regex_threat(
    pattern: re.Pattern,
    match: re.Match,
    category: str,
    pattern_start: float,
    context: str = "unknown",
    binary_prefix: list[int] | None = None,
) -> dict[str, Any] | None:
    for candidate, is_valid_threat in _CANDIDATE_REJECTION_VALIDATORS:
        if pattern.pattern == candidate and not is_valid_threat(match, context):
            return None
    if pattern.pattern in RECON_OPTIONAL_SEPARATOR_PATTERN_SOURCES and not (
        _recon_path_value_is_probe(match, context)
    ):
        return None
    if pattern.pattern in NOISE_PRONE_PATTERN_SOURCES and match_is_binary_dense(
        binary_prefix, match
    ):
        return None
    return {
        "type": "regex",
        "pattern": pattern.pattern,
        "match": _sanitize_for_reporting(match.group()),
        "position": match.start(),
        "execution_time": time.monotonic() - pattern_start,
        "category": category,
        "weight": _resolve_pattern_weight(pattern.pattern, category),
    }


def _build_timeout_threat(
    pattern: re.Pattern, category: str, pattern_start: float
) -> dict[str, Any]:
    return {
        "type": "pattern_timeout",
        "pattern": pattern.pattern,
        "match": "",
        "position": 0,
        "execution_time": time.monotonic() - pattern_start,
        "category": category,
        "weight": _resolve_pattern_weight(pattern.pattern, category),
    }


def _first_accepted_regex_threat(
    matches: Iterator[re.Match],
    pattern: re.Pattern,
    category: str,
    pattern_start: float,
    context: str = "unknown",
    binary_prefix: list[int] | None = None,
) -> dict[str, Any] | None:
    for match in matches:
        threat = _build_regex_threat(
            pattern, match, category, pattern_start, context, binary_prefix
        )
        if threat:
            return threat
    return None


class _SusPatternsRegexMixin(_SusPatternsRegistryMixin, _SusPatternsEnhancedMixin):
    def _check_regex_pattern(
        self,
        pattern: re.Pattern,
        content: str,
        ip_address: str,
        pattern_start: float,
        category: str,
        *,
        state: _DetectionState | None = None,
        context: str = "unknown",
        binary_prefix: list[int] | None = None,
    ) -> tuple[dict | None, bool]:
        state = self._resolve_state(state)
        windowed_finder = _WINDOWED_PATTERN_FINDERS.get(pattern.pattern)
        if windowed_finder is not None:
            return self._check_windowed_pattern(
                pattern,
                windowed_finder,
                content,
                pattern_start,
                category,
                context,
                binary_prefix,
            )

        timeout_occurred = False

        scan_window_matcher = _PATTERN_SCAN_WINDOW_MATCHERS.get(pattern.pattern)
        if scan_window_matcher is not None:
            matches = scan_window_matcher(content, pattern)
            threat = _first_accepted_regex_threat(
                iter(matches),
                pattern,
                category,
                pattern_start,
                context,
                binary_prefix,
            )
            return threat, timeout_occurred

        scan_window_bounds = _SCAN_WINDOW_PATTERNS.get(pattern.pattern)
        if scan_window_bounds is not None:
            scan_window_matches = _iter_scan_window_matches(
                content, pattern, scan_window_bounds
            )
            threat = _first_accepted_regex_threat(
                scan_window_matches,
                pattern,
                category,
                pattern_start,
                context,
                binary_prefix,
            )
            return threat, timeout_occurred

        compiler = state.compiler

        if compiler:
            safe_finder = compiler.create_async_safe_finditer_matcher(
                pattern, inline_safe=category != "custom"
            )
            matches = safe_finder(content)
            timeout_threshold = 0.9 * compiler.default_timeout
            if not matches and time.monotonic() - pattern_start >= timeout_threshold:
                timeout_occurred = True
                logger.warning(
                    "Pattern timeout: "
                    f"{_redact_pattern_source(pattern.pattern)[:50]}..."
                )

            threat = _first_accepted_regex_threat(
                iter(matches),
                pattern,
                category,
                pattern_start,
                context,
                binary_prefix,
            )
            if threat:
                return threat, timeout_occurred
        else:
            threat, timeout_occurred = self._check_regex_pattern_with_retry(
                pattern,
                content,
                ip_address,
                pattern_start,
                category,
                context,
                binary_prefix,
            )
            if threat:
                return threat, timeout_occurred

        return None, timeout_occurred

    def _check_windowed_pattern(
        self,
        pattern: re.Pattern,
        finder: Callable[[str], Iterator[re.Match]],
        content: str,
        pattern_start: float,
        category: str,
        context: str,
        binary_prefix: list[int] | None = None,
    ) -> tuple[dict | None, bool]:
        timeout = getattr(
            self._config, "detection_compiler_timeout", _DEFAULT_COMPILER_TIMEOUT
        )
        timeout = _clamp_to_scan_time_budget(timeout)
        future = shared_regex_executor().submit(lambda: list(finder(content)))
        try:
            matches = _await_regex_future(future, timeout)
            report_scan_success()
        except concurrent.futures.TimeoutError:
            logger.warning(
                f"Pattern timeout: {_redact_pattern_source(pattern.pattern)[:50]}..."
            )
            future.cancel()
            report_scan_timeout()
            return None, True
        except Exception as e:
            logger.error(
                f"Error in windowed regex search for pattern "
                f"{_redact_pattern_source(pattern.pattern)[:50]}...: {e}"
            )
            return None, False

        threat = _first_accepted_regex_threat(
            iter(matches), pattern, category, pattern_start, context, binary_prefix
        )
        return threat, False

    def _check_regex_pattern_with_retry(
        self,
        pattern: re.Pattern,
        content: str,
        ip_address: str,
        pattern_start: float,
        category: str,
        context: str = "unknown",
        binary_prefix: list[int] | None = None,
    ) -> tuple[dict | None, bool]:
        search_from = 0
        timeout_occurred = False

        while True:
            match, occurred = self._check_pattern_with_timeout(
                pattern, content, ip_address, pattern_start, search_from
            )
            timeout_occurred = timeout_occurred or occurred
            if match is None or occurred:
                break

            threat = _build_regex_threat(
                pattern, match, category, pattern_start, context, binary_prefix
            )
            if threat:
                return threat, timeout_occurred

            search_from = (
                match.end() + 1 if match.end() == match.start() else match.end()
            )

        return None, timeout_occurred

    def _check_pattern_with_timeout(
        self,
        pattern: re.Pattern,
        content: str,
        ip_address: str,
        pattern_start: float,
        search_from: int = 0,
    ) -> tuple[re.Match | None, bool]:
        timeout = getattr(
            self._config, "detection_compiler_timeout", _DEFAULT_COMPILER_TIMEOUT
        )
        timeout = _clamp_to_scan_time_budget(timeout)
        future = shared_regex_executor().submit(pattern.search, content, search_from)
        try:
            match = _await_regex_future(future, timeout)
            report_scan_success()
            return match, False
        except concurrent.futures.TimeoutError:
            logger.warning(
                f"Regex timeout exceeded for pattern: "
                f"{_redact_pattern_source(pattern.pattern)[:50]}... "
                f"Potential ReDoS attack blocked. IP: {ip_address}"
            )
            future.cancel()
            report_scan_timeout()
            return None, True
        except Exception as e:
            logger.error(
                f"Error in regex search for pattern "
                f"{_redact_pattern_source(pattern.pattern)[:50]}...: {e}"
            )
            return None, False

    _KNOWN_CONTEXTS = frozenset(
        {"query_param", "header", "url_path", "request_body", "unknown"}
    )

    @staticmethod
    def _normalize_context(context: str | None) -> str:
        if context is None:
            return "unknown"
        normalized = context.split(":", 1)[0]
        if normalized not in _SusPatternsRegexMixin._KNOWN_CONTEXTS:
            return "unknown"
        return normalized

    def _check_regex_patterns(
        self,
        content: str,
        ip_address: str,
        correlation_id: str | None,
        context: str = "unknown",
        enabled_categories: set[str] | None = None,
        *,
        state: _DetectionState | None = None,
        raw_view_only: bool | None = None,
        url_decoded_view_only: bool | None = None,
    ) -> tuple[list[dict], list[str], list[str]]:
        state = self._resolve_state(state)
        threats = []
        matched_patterns = []
        timeouts = []

        all_patterns = self.get_all_compiled_patterns()
        normalized = self._normalize_context(context)
        validator_context = (
            f"{normalized}{_EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX}"
            if context.endswith(_EMBEDDED_JSON_LEAF_CONTEXT_SUFFIX)
            else normalized
        )
        skip_filter = normalized in ("unknown", "request_body")
        performance_monitor = state.performance_monitor
        binary_prefix = build_binary_prefix(content)

        slice_start = time.monotonic()
        for pattern, contexts, category in all_patterns:
            if _scan_time_budget_exhausted():
                budget_threat = _scan_time_budget_exhausted_threat(
                    _resolve_pattern_weight(
                        _SCAN_TIME_BUDGET_EXHAUSTED_PATTERN, "custom"
                    )
                )
                _warn_scan_time_cap_reached_once(ip_address)
                threats.append(budget_threat)
                matched_patterns.append(budget_threat["pattern"])
                timeouts.append(budget_threat["pattern"])
                break
            if _pattern_should_be_skipped(
                pattern,
                contexts,
                category,
                raw_view_only=raw_view_only,
                skip_filter=skip_filter,
                normalized_context=normalized,
                enabled_categories=enabled_categories,
                url_decoded_view_only=url_decoded_view_only,
            ):
                continue

            pattern_start = time.monotonic()

            scan_content = content
            threat, timeout_occurred = self._check_regex_pattern(
                pattern,
                scan_content,
                ip_address,
                pattern_start,
                category,
                state=state,
                context=validator_context,
                binary_prefix=binary_prefix,
            )

            pattern_end = time.monotonic()
            _record_scan_time(pattern_end - pattern_start)
            if pattern_end - slice_start >= _EVENT_LOOP_SLICE_SECONDS:
                _yield_to_event_loop()
                slice_start = time.monotonic()

            if timeout_occurred:
                timeouts.append(pattern.pattern)
                if not threat:
                    threat = _build_timeout_threat(pattern, category, pattern_start)

            if threat:
                threats.append(threat)
                matched_patterns.append(pattern.pattern)

            if performance_monitor:
                performance_monitor.record_metric(
                    pattern=pattern.pattern,
                    execution_time=time.monotonic() - pattern_start,
                    content_length=len(content),
                    matched=bool(threat),
                    timeout=timeout_occurred,
                    agent_handler=self.agent_handler,
                    correlation_id=correlation_id,
                )

        return threats, matched_patterns, timeouts
