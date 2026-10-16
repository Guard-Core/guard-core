import contextvars
import logging
import re
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any, TypeVar

from guard_core.sync._utils.detection_config import (
    _DEFAULT_BINARY_MIN_RUN_LENGTH,
    _DEFAULT_MAX_JSON_DEPTH,
    _DEFAULT_MAX_SCAN_CHARS,
    _DEFAULT_MAX_SCAN_SECONDS,
    _DEFAULT_MAX_SCAN_VALUES,
)
from guard_core.sync._utils.logging_utils import _log_at_level, _sanitize_for_reporting
from guard_core.sync._utils.pattern_source_redaction import _redact_pattern_source

logger = logging.getLogger("guard_core")

_T = TypeVar("_T")

_scanned_value_count: contextvars.ContextVar[int] = contextvars.ContextVar(
    "guard_core_detection_scanned_value_count", default=0
)
_scan_value_cap: contextvars.ContextVar[int] = contextvars.ContextVar(
    "guard_core_detection_scan_value_cap", default=_DEFAULT_MAX_SCAN_VALUES
)
_scanned_char_count: contextvars.ContextVar[int] = contextvars.ContextVar(
    "guard_core_detection_scanned_char_count", default=0
)
_scan_char_cap: contextvars.ContextVar[int] = contextvars.ContextVar(
    "guard_core_detection_scan_char_cap", default=_DEFAULT_MAX_SCAN_CHARS
)
_scan_char_cap_warned: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "guard_core_detection_scan_char_cap_warned", default=False
)
_scan_time_cap_warned: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "guard_core_detection_scan_time_cap_warned", default=False
)
_json_depth_cap: contextvars.ContextVar[int] = contextvars.ContextVar(
    "guard_core_detection_json_depth_cap", default=_DEFAULT_MAX_JSON_DEPTH
)
_json_depth_warned: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "guard_core_detection_json_depth_warned", default=False
)
_binary_min_run: contextvars.ContextVar[int] = contextvars.ContextVar(
    "guard_core_detection_binary_min_run", default=_DEFAULT_BINARY_MIN_RUN_LENGTH
)
_scan_time_cap: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "guard_core_detection_scan_time_cap", default=None
)
_scan_time_spent: contextvars.ContextVar[float] = contextvars.ContextVar(
    "guard_core_detection_scan_time_spent", default=0.0
)
_scan_cpu_mark: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "guard_core_detection_scan_cpu_mark", default=None
)
_scan_slice_start: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "guard_core_detection_scan_slice_start", default=None
)
_semantic_excluded_headers: contextvars.ContextVar[frozenset[str]] = (
    contextvars.ContextVar(
        "guard_core_detection_semantic_excluded_headers", default=frozenset()
    )
)


@contextmanager
def _scan_value_budget(
    max_values: int,
    max_json_depth: int = _DEFAULT_MAX_JSON_DEPTH,
    max_scan_chars: int = _DEFAULT_MAX_SCAN_CHARS,
    binary_min_run_length: int = _DEFAULT_BINARY_MIN_RUN_LENGTH,
    max_scan_seconds: float = _DEFAULT_MAX_SCAN_SECONDS,
    semantic_excluded_headers: frozenset[str] = frozenset(),
) -> Iterator[None]:
    count_token = _scanned_value_count.set(0)
    cap_token = _scan_value_cap.set(max_values)
    char_count_token = _scanned_char_count.set(0)
    char_cap_token = _scan_char_cap.set(max_scan_chars)
    char_warned_token = _scan_char_cap_warned.set(False)
    depth_cap_token = _json_depth_cap.set(max_json_depth)
    depth_warned_token = _json_depth_warned.set(False)
    binary_run_token = _binary_min_run.set(binary_min_run_length)
    time_cap_token = _scan_time_cap.set(max_scan_seconds)
    time_spent_token = _scan_time_spent.set(0.0)
    time_warned_token = _scan_time_cap_warned.set(False)
    slice_token = _scan_slice_start.set(time.monotonic())
    semantic_token = _semantic_excluded_headers.set(semantic_excluded_headers)
    try:
        yield
    finally:
        _scanned_value_count.reset(count_token)
        _scan_value_cap.reset(cap_token)
        _scanned_char_count.reset(char_count_token)
        _scan_char_cap.reset(char_cap_token)
        _scan_char_cap_warned.reset(char_warned_token)
        _json_depth_cap.reset(depth_cap_token)
        _json_depth_warned.reset(depth_warned_token)
        _binary_min_run.reset(binary_run_token)
        _scan_time_cap.reset(time_cap_token)
        _scan_time_spent.reset(time_spent_token)
        _scan_time_cap_warned.reset(time_warned_token)
        _scan_slice_start.reset(slice_token)
        _semantic_excluded_headers.reset(semantic_token)


def _binary_island_min_run_length() -> int:
    return _binary_min_run.get()


def _scan_time_remaining() -> float | None:
    cap = _scan_time_cap.get()
    return None if cap is None else cap - _scan_time_spent.get()


_SCAN_TIME_BUDGET_EXHAUSTED_PATTERN = "scan_time_budget_exhausted"
_EVENT_LOOP_SLICE_SECONDS = 0.002


def _scan_time_budget_exhausted_threat(weight: float) -> dict[str, Any]:
    return {
        "type": "pattern_timeout",
        "pattern": _SCAN_TIME_BUDGET_EXHAUSTED_PATTERN,
        "match": "",
        "position": 0,
        "execution_time": 0.0,
        "category": "custom",
        "weight": weight,
    }


def _thread_cpu_seconds() -> float:
    return time.thread_time()


def _record_scan_time(elapsed: float) -> None:
    _scan_time_spent.set(_scan_time_spent.get() + elapsed)


def _open_cpu_pass() -> contextvars.Token[float | None]:
    return _scan_cpu_mark.set(
        None if _scan_time_cap.get() is None else _thread_cpu_seconds()
    )


def _close_cpu_pass(token: contextvars.Token[float | None]) -> None:
    _charge_inline_cpu()
    _scan_cpu_mark.reset(token)


def _charge_inline_cpu() -> None:
    mark = _scan_cpu_mark.get()
    if mark is not None:
        now = _thread_cpu_seconds()
        _record_scan_time(now - mark)
        _scan_cpu_mark.set(now)


def _restart_inline_cpu() -> None:
    if _scan_cpu_mark.get() is not None:
        _scan_cpu_mark.set(_thread_cpu_seconds())


def _suspended(awaitable: _T) -> _T:
    _charge_inline_cpu()
    try:
        return awaitable
    finally:
        _restart_inline_cpu()


def _timed_in_worker(
    work: Callable[[], Any], cpu_sink: list[float]
) -> Callable[[], Any]:
    def run() -> Any:
        start = _thread_cpu_seconds()
        try:
            return work()
        finally:
            cpu_sink.append(_thread_cpu_seconds() - start)

    return run


def _scan_time_budget_exhausted() -> bool:
    remaining = _scan_time_remaining()
    return remaining is not None and remaining <= 0.0


def _warn_scan_time_cap_reached_once(client_ip: str) -> None:
    if _scan_time_cap_warned.get():
        return
    _scan_time_cap_warned.set(True)
    logger.warning(
        "detection_max_scan_seconds (%s) reached for client %s; remaining "
        "patterns and request values are not scanned",
        _scan_time_cap.get(),
        client_ip,
    )


def _context_header_is_semantic_excluded(context: str) -> bool:
    excluded = _semantic_excluded_headers.get()
    if not excluded:
        return False
    kind, _, rest = context.partition(":")
    if kind != "header":
        return False
    name = rest.removesuffix(":embedded_json")
    return name.strip().lower() in excluded


def _scan_value_budget_exhausted(client_ip: str) -> bool:
    count = _scanned_value_count.get() + 1
    _scanned_value_count.set(count)
    cap = _scan_value_cap.get()
    if count <= cap:
        return False
    if count == cap + 1:
        logger.warning(
            "detection_max_scan_values (%d) reached for client %s; remaining "
            "request values are not scanned",
            cap,
            client_ip,
        )
    return True


def _scan_char_budget_exhausted(client_ip: str, value_length: int) -> bool:
    consumed_before = _scanned_char_count.get()
    cap = _scan_char_cap.get()
    if consumed_before >= cap:
        if not _scan_char_cap_warned.get():
            _scan_char_cap_warned.set(True)
            logger.warning(
                "detection_max_scan_chars (%d) reached for client %s; remaining "
                "request values are not scanned",
                cap,
                client_ip,
            )
        return True
    _scanned_char_count.set(consumed_before + value_length)
    return False


def _scan_budget_exhausted(client_ip: str, value: str) -> bool:
    if _scan_value_budget_exhausted(client_ip):
        return True
    return _scan_char_budget_exhausted(client_ip, len(value))


def _json_depth_cap_value() -> int:
    return _json_depth_cap.get()


def _warn_json_depth_cap_reached_once(client_ip: str) -> None:
    if _json_depth_warned.get():
        return
    _json_depth_warned.set(True)
    logger.warning(
        "detection_max_json_depth (%d) reached for client %s; nested content "
        "below that depth is scanned as text",
        _json_depth_cap.get(),
        client_ip,
    )


def _build_threat_message(threat: dict[str, Any]) -> str:
    if threat["type"] == "regex":
        return f"Value matched pattern '{_redact_pattern_source(threat['pattern'])}'"
    elif threat["type"] == "semantic":
        attack_type = threat.get("attack_type", "suspicious")
        score = threat.get("probability", threat.get("threat_score", 0))
        return f"Semantic attack: {attack_type} (score: {score:.2f})"
    elif threat["type"] == "pattern_timeout":
        return (
            f"Pattern exceeded scan time budget: "
            f"'{_redact_pattern_source(threat['pattern'])}'"
        )
    return "Threat detected"


def _build_threats_message(threats: list[dict[str, Any]]) -> str:
    message = _build_threat_message(threats[0])
    if threats[0]["type"] == "pattern_timeout":
        return message
    timeout = next((t for t in threats[1:] if t["type"] == "pattern_timeout"), None)
    if timeout is None:
        return message
    return f"{message}; {_build_threat_message(timeout)}"


_MAX_USER_AGENT_MATCH_LENGTH = 512


def _user_agent_matches_blocked_pattern(user_agent: str, patterns: list[str]) -> bool:
    from guard_core.sync.detection_engine.compiler import PatternCompiler

    subject = user_agent[:_MAX_USER_AGENT_MATCH_LENGTH]
    compiler = PatternCompiler()
    for pattern in patterns:
        finder = compiler.create_async_safe_finditer_matcher(pattern, inline_safe=True)
        if finder(subject):
            return True
    return False


def _fallback_pattern_check(
    value: str, client_ip: str, context: str
) -> tuple[bool, str]:
    from guard_core.sync.detection_engine.binary_prefix import build_binary_prefix
    from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

    normalized_context = sus_patterns_handler._normalize_context(context)
    all_compiled = sus_patterns_handler.get_all_compiled_patterns()
    binary_prefix = build_binary_prefix(value)
    for pattern, _contexts, category in all_compiled:
        if _scan_time_budget_exhausted():
            return True, "Scan time budget exhausted (fallback)"
        pattern_start = time.monotonic()
        try:
            threat, _timeout_occurred = sus_patterns_handler._check_regex_pattern(
                pattern,
                value,
                client_ip,
                pattern_start,
                category,
                context=normalized_context,
                binary_prefix=binary_prefix,
            )
        except RecursionError:
            logger.warning(
                "Fallback pattern search hit the regex engine's recursion "
                "limit on pattern %r; skipping it and continuing the "
                "fallback scan",
                _redact_pattern_source(pattern.pattern),
            )
            continue
        if threat:
            return True, "Value matched pattern (fallback)"
    return False, ""


def _resolve_json_redact_all(
    content_preview: str | None, json_redact_all: bool | None
) -> bool:
    if json_redact_all is not None:
        return json_redact_all
    return content_preview is not None


def _check_embedded_json_if_applicable(
    value: str,
    context: str,
    client_ip: str,
    correlation_id: str,
    enabled_categories: set[str] | None,
    scan_embedded_json: bool,
    content_preview: str | None,
    sensitive_body_fields: frozenset[str],
    excluded_body_fields: frozenset[str],
    json_redact_all: bool | None,
    sensitive_params: frozenset[str] = frozenset(),
) -> tuple[bool, str, list[dict], str | None] | None:
    if not scan_embedded_json or context == "request_body":
        return None

    from guard_core.sync._utils.embedded_json_scan import _check_embedded_json

    json_result = _check_embedded_json(
        value,
        context,
        client_ip,
        correlation_id,
        enabled_categories,
        excluded_body_fields,
        sensitive_body_fields,
        redact_all=_resolve_json_redact_all(content_preview, json_redact_all),
        sensitive_params=sensitive_params,
    )
    if json_result is None or not json_result[0]:
        return None
    return json_result


def _check_value_enhanced(
    value: str,
    context: str,
    client_ip: str,
    correlation_id: str,
    enabled_categories: set[str] | None = None,
    scan_embedded_json: bool = True,
    content_preview: str | None = None,
    sensitive_body_fields: frozenset[str] = frozenset(),
    excluded_body_fields: frozenset[str] = frozenset(),
    json_redact_all: bool | None = None,
    sensitive_params: frozenset[str] = frozenset(),
) -> tuple[bool, str, list[dict], str | None]:
    from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler

    if _scan_budget_exhausted(client_ip, value):
        return False, "", [], None

    json_hit = _check_embedded_json_if_applicable(
        value,
        context,
        client_ip,
        correlation_id,
        enabled_categories,
        scan_embedded_json,
        content_preview,
        sensitive_body_fields,
        excluded_body_fields,
        json_redact_all,
        sensitive_params,
    )
    if json_hit is not None:
        return json_hit

    try:
        result = sus_patterns_handler.detect(
            content=value,
            ip_address=client_ip,
            context=context,
            correlation_id=correlation_id,
            enabled_categories=enabled_categories,
            content_preview=content_preview,
        )

        if not result["is_threat"]:
            return False, "", [], None

        threats: list[dict] = list(result.get("threats", []))
        if threats:
            return True, _build_threats_message(threats), threats, None

        return True, "Threat detected", threats, None

    except RecursionError:
        raise
    except Exception as e:
        logger.error(f"Enhanced detection failed: {e}, falling back to basic check")
        detected, trigger = _fallback_pattern_check(value, client_ip, context)
        return detected, trigger, [], None


def _log_detected_component(
    value: str, component_name: str, client_ip: str, log_level: str | None
) -> None:
    if log_level is None:
        return
    message = "Potential attack detected from"
    details = (
        f"{client_ip}: {value[:100]}..."
        if len(value) > 100
        else f"{client_ip}: {value}"
    )
    reason_message = f"Suspicious pattern in {component_name}"
    _log_at_level(logger, log_level, f"{message} {details} - {reason_message}")


def _check_request_component(
    value: str,
    context: str,
    component_name: str,
    client_ip: str,
    correlation_id: str,
    enabled_categories: set[str] | None,
    log_level: str | None,
    scan_embedded_json: bool = True,
    content_preview: str | None = None,
    sensitive_body_fields: frozenset[str] = frozenset(),
    excluded_body_fields: frozenset[str] = frozenset(),
    json_redact_all: bool | None = None,
    sensitive_params: frozenset[str] = frozenset(),
) -> tuple[bool, str, list[dict]]:
    detected, trigger, threats, log_override = _check_value_enhanced(
        value,
        context,
        client_ip,
        correlation_id,
        enabled_categories,
        scan_embedded_json,
        content_preview=content_preview,
        sensitive_body_fields=sensitive_body_fields,
        excluded_body_fields=excluded_body_fields,
        json_redact_all=json_redact_all,
        sensitive_params=sensitive_params,
    )
    if detected:
        fallback = content_preview if content_preview is not None else value
        _log_detected_component(
            log_override if log_override is not None else fallback,
            component_name,
            client_ip,
            log_level,
        )
    return detected, trigger, threats


def _scan_component_name(
    name: str,
    context: str,
    label: str,
    enabled_categories: set[str] | None,
    client_ip: str,
    correlation_id: str,
    log_level: str | None,
    content_preview: str | None = None,
) -> tuple[bool, str, list[dict]]:
    return _check_request_component(
        name,
        context,
        label,
        client_ip,
        correlation_id,
        enabled_categories,
        log_level,
        scan_embedded_json=False,
        content_preview=content_preview,
    )


def _check_always_scan_header(value: str) -> tuple[bool, str, list[dict]]:
    from guard_core.sync.handlers.suspatterns_handler import ALWAYS_SCAN_HEADER_PATTERNS

    for pattern in ALWAYS_SCAN_HEADER_PATTERNS:
        match = pattern.search(value)
        if match:
            threat = {
                "type": "regex",
                "pattern": pattern.pattern,
                "match": _sanitize_for_reporting(match.group()),
                "position": match.start(),
                "category": "cmd_injection",
            }
            trigger = (
                f"Value matched pattern '{_redact_pattern_source(pattern.pattern)}'"
            )
            return True, trigger, [threat]
    return False, "", []


def _compiler_finditer(
    compiler: Any, pattern: re.Pattern, category: str, content: str
) -> list[re.Match]:
    if category != "custom":
        inline_finder = compiler.create_async_safe_finditer_matcher(
            pattern, inline_safe=True
        )
        inline_matches: list[re.Match] = inline_finder(content)
        return inline_matches
    worker_cpu: list[float] = []
    finder = compiler.create_async_safe_finditer_matcher(
        pattern,
        inline_safe=False,
        worker_wrapper=lambda work: _timed_in_worker(work, worker_cpu),
    )
    matches: list[re.Match] = _suspended(finder(content))
    _record_scan_time(sum(worker_cpu) if worker_cpu else compiler.default_timeout)
    return matches
