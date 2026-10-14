import json
import logging
import re
from collections.abc import Callable
from typing import Any, Literal
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from guard_core._utils.block_events import fire_block_hook
from guard_core._utils.ip_extraction import UNKNOWN_CLIENT_IDENTITY, _canonicalize_ip
from guard_core._utils.logging_utils import (
    _json_depth_cap_hit,
    _log_at_level,
    _redact_sensitive_json,
)
from guard_core._utils.pair_redaction import (
    _bounded_percent_decode,
    _redact_pairs_in_text,
)
from guard_core._utils.pair_value_scan import _QUOTE_CHARS
from guard_core.protocols.request_protocol import GuardRequest

_DEFAULT_SENSITIVE_LOG_HEADERS: frozenset[str] = frozenset(
    {"authorization", "proxy-authorization", "cookie", "x-api-key"}
)

_DEFAULT_SENSITIVE_LOG_FIELDS: frozenset[str] = frozenset(
    {
        "access_token",
        "refresh_token",
        "api_key",
        "apikey",
        "token",
        "password",
        "secret",
        "client_secret",
        "signature",
    }
)


def _merge_sensitive_names(
    defaults: frozenset[str], extra: frozenset[str] | None
) -> frozenset[str]:
    if extra is None:
        return defaults
    return defaults | {name.lower() for name in extra}


def _merge_sensitive_log_headers(extra: frozenset[str] | None) -> frozenset[str]:
    return _merge_sensitive_names(_DEFAULT_SENSITIVE_LOG_HEADERS, extra)


def _resolve_json_depth_cap() -> int:
    from guard_core._utils.detection_scan import _json_depth_cap_value

    return _json_depth_cap_value()


def _json_redact_text(
    text: str,
    sensitive: frozenset[str],
    sensitive_body_fields: frozenset[str],
    max_depth: int,
) -> str | None:
    try:
        parsed = json.loads(text)
        if not isinstance(parsed, dict | list):
            return None
        _json_depth_cap_hit.set(False)
        redacted = _redact_sensitive_json(
            parsed, sensitive, sensitive_body_fields, max_depth
        )
        if _json_depth_cap_hit.get():
            return "[REDACTED]"
        if redacted == parsed:
            return None
        return json.dumps(redacted, separators=(",", ":"), ensure_ascii=False)
    except RecursionError:
        return "[REDACTED]"
    except ValueError:
        return None


def _redact_json_or_pairs_segment(
    segment: str,
    sensitive: frozenset[str],
    sensitive_body_fields: frozenset[str],
    max_depth: int,
) -> str:
    decoded = _bounded_percent_decode(segment, unquote)
    redacted_text = _json_redact_text(
        decoded, sensitive, sensitive_body_fields, max_depth
    )
    if redacted_text is not None:
        return quote(redacted_text, safe="")
    return _redact_pairs_in_text(segment, sensitive, sensitive_body_fields, max_depth)


def _redact_path_segment(
    segment: str,
    sensitive: frozenset[str],
    sensitive_body_fields: frozenset[str],
    max_depth: int,
) -> str:
    proper, sep, rest = segment.partition(";")
    redacted_proper = _redact_json_or_pairs_segment(
        proper, sensitive, sensitive_body_fields, max_depth
    )
    if not sep:
        return redacted_proper
    redacted_rest = _redact_json_or_pairs_segment(
        rest, sensitive, sensitive_body_fields, max_depth
    )
    return ";".join([redacted_proper, redacted_rest])


def _redact_whole_path_as_json(
    path: str,
    sensitive: frozenset[str],
    sensitive_body_fields: frozenset[str],
    max_depth: int,
) -> str | None:
    prefix = "/" if path.startswith("/") else ""
    decoded = _bounded_percent_decode(path[len(prefix) :], unquote)
    redacted_text = _json_redact_text(
        decoded, sensitive, sensitive_body_fields, max_depth
    )
    return None if redacted_text is None else f"{prefix}{redacted_text}"


def _split_path_segments(path: str) -> list[str]:
    segments: list[str] = []
    current: list[str] = []
    quote_char = ""
    escaped = False
    for ch in path:
        if quote_char:
            current.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote_char:
                quote_char = ""
            continue
        if ch in _QUOTE_CHARS:
            quote_char = ch
            current.append(ch)
            continue
        if ch == "/":
            segments.append("".join(current))
            current = []
            continue
        current.append(ch)
    segments.append("".join(current))
    return segments


def _redact_sensitive_path(
    path: str,
    sensitive: frozenset[str],
    sensitive_body_fields: frozenset[str],
    max_depth: int,
) -> str:
    whole = _redact_whole_path_as_json(
        path, sensitive, sensitive_body_fields, max_depth
    )
    if whole is not None:
        return whole
    return "/".join(
        _redact_path_segment(segment, sensitive, sensitive_body_fields, max_depth)
        for segment in _split_path_segments(path)
    )


def _merge_sensitive_log_body_fields(extra: frozenset[str] | None) -> frozenset[str]:
    return _merge_sensitive_names(_DEFAULT_SENSITIVE_LOG_FIELDS, extra)


def _redact_sensitive_headers(
    headers: dict[str, str],
    sensitive_headers: frozenset[str] | None,
    sensitive_body_fields: frozenset[str] | None = None,
    sensitive_params: frozenset[str] | None = None,
) -> dict[str, str]:
    sensitive = _merge_sensitive_log_headers(sensitive_headers)
    return {
        key: "[REDACTED]"
        if key.strip().lower() in sensitive
        else redact_blob_for_display(
            value, sensitive_params, sensitive_body_fields, sensitive_headers
        )
        for key, value in headers.items()
    }


_URL_UNSAFE_CONTROL_TRANSLATION = str.maketrans({"\t": "%09", "\r": "%0D", "\n": "%0A"})


def _escape_url_unsafe_controls(url: str) -> str:
    if not any(ch in url for ch in "\t\r\n"):
        return url
    return url.translate(_URL_UNSAFE_CONTROL_TRANSLATION)


def _redact_netloc_password(netloc: str) -> str:
    if "@" not in netloc:
        return netloc
    userinfo, _, hostport = netloc.rpartition("@")
    if ":" not in userinfo:
        return netloc
    user, _, _ = userinfo.partition(":")
    return f"{user}:[REDACTED]@{hostport}"


def redact_url_for_display(
    url: str,
    sensitive_params: frozenset[str] | None,
    sensitive_body_fields: frozenset[str] | None = None,
    sensitive_headers: frozenset[str] | None = None,
) -> str:
    escaped_url = _escape_url_unsafe_controls(url)
    parts = urlsplit(escaped_url)
    body_fields = _merge_sensitive_log_body_fields(sensitive_body_fields)
    sensitive = _merged_sensitive_names(
        sensitive_params, body_fields, sensitive_headers
    )
    max_depth = _resolve_json_depth_cap()
    redacted_path = _redact_sensitive_path(
        parts.path, sensitive, body_fields, max_depth
    )
    if (
        not parts.query
        and not parts.fragment
        and "@" not in parts.netloc
        and redacted_path == parts.path
    ):
        return escaped_url
    redacted_query = _redact_json_or_pairs_segment(
        parts.query, sensitive, body_fields, max_depth
    )
    redacted_fragment = _redact_json_or_pairs_segment(
        parts.fragment, sensitive, body_fields, max_depth
    )
    return urlunsplit(
        (
            parts.scheme,
            _redact_netloc_password(parts.netloc),
            redacted_path,
            redacted_query,
            redacted_fragment,
        )
    )


_redact_sensitive_query_params = redact_url_for_display


def redact_endpoint_for_display(
    value: str,
    sensitive_params: frozenset[str] | None,
    sensitive_body_fields: frozenset[str] | None = None,
    sensitive_headers: frozenset[str] | None = None,
) -> str:
    return redact_url_for_display(
        value, sensitive_params, sensitive_body_fields, sensitive_headers
    )


_XML_ELEMENT_RE = re.compile(r"<([A-Za-z_][\w.:-]*)>([^<]*)</\1>")


def _redact_xml_elements(text: str, sensitive: frozenset[str]) -> str:
    def _redact(match: re.Match[str]) -> str:
        name = match.group(1)
        if name.lower() not in sensitive:
            return match.group(0)
        return f"<{name}>[REDACTED]</{name}>"

    return _XML_ELEMENT_RE.sub(_redact, text)


def _merged_sensitive_names(
    sensitive_params: frozenset[str] | None,
    sensitive_body_fields: frozenset[str],
    sensitive_headers: frozenset[str] | None = None,
) -> frozenset[str]:
    return (
        _merge_sensitive_names(_DEFAULT_SENSITIVE_LOG_FIELDS, sensitive_params)
        | sensitive_body_fields
        | _merge_sensitive_log_headers(sensitive_headers)
    )


def redact_blob_for_display(
    text: str,
    sensitive_params: frozenset[str] | None,
    sensitive_body_fields: frozenset[str] | None,
    sensitive_headers: frozenset[str] | None = None,
) -> str:
    max_depth = _resolve_json_depth_cap()
    body_fields = _merge_sensitive_log_body_fields(sensitive_body_fields)
    sensitive = _merged_sensitive_names(
        sensitive_params, body_fields, sensitive_headers
    )
    json_redacted = _json_redact_text(text, sensitive, body_fields, max_depth)
    if json_redacted is None:
        json_redacted = _json_redact_text(
            _bounded_percent_decode(text), sensitive, body_fields, max_depth
        )
    if json_redacted is not None:
        return json_redacted
    xml_redacted = _redact_xml_elements(text, sensitive)
    return _redact_pairs_in_text(xml_redacted, sensitive, body_fields, max_depth)


def redact_header_value_for_display(
    value: str,
    sensitive_params: frozenset[str] | None,
    sensitive_body_fields: frozenset[str] | None,
    sensitive_headers: frozenset[str] | None = None,
) -> str:
    if not value:
        return value
    return redact_blob_for_display(
        value, sensitive_params, sensitive_body_fields, sensitive_headers
    )


def _extract_request_context(
    request: GuardRequest,
    sensitive_headers: frozenset[str] | None,
    sensitive_params: frozenset[str] | None,
    sensitive_body_fields: frozenset[str] | None = None,
) -> dict[str, Any]:
    cached_ip = getattr(request.state, "client_ip", None)
    if cached_ip:
        client_ip = cached_ip
    elif request.client_host:
        client_ip = _canonicalize_ip(request.client_host)
    else:
        client_ip = UNKNOWN_CLIENT_IDENTITY

    return {
        "client_ip": client_ip,
        "method": request.method,
        "url": _redact_sensitive_query_params(
            request.url_full, sensitive_params, sensitive_body_fields, sensitive_headers
        ),
        "headers": _redact_sensitive_headers(
            dict(request.headers),
            sensitive_headers,
            sensitive_body_fields,
            sensitive_params,
        ),
    }


def _build_log_message_for_request(context: dict[str, Any]) -> tuple[str, str]:
    message = "Request from"
    details = f"{message} {context['client_ip']}: {context['method']} {context['url']}"
    reason_message = f"Headers: {context['headers']}"
    return details, reason_message


def _build_log_message_for_suspicious(
    context: dict[str, Any], reason: str, passive_mode: bool, trigger_info: str
) -> tuple[str, str]:
    if passive_mode:
        label = "Penetration attempt" if trigger_info else "Suspicious activity"
        message = f"[PASSIVE MODE] {label} detected from"
        details = (
            f"{message} {context['client_ip']}: {context['method']} {context['url']}"
        )

        if trigger_info:
            reason_message = f"Trigger: {trigger_info} - Headers: {context['headers']}"
        else:
            reason_message = f"Reason: {reason} - Headers: {context['headers']}"
    else:
        message = "Suspicious activity detected from"
        details = (
            f"{message} {context['client_ip']}: {context['method']} {context['url']}"
        )
        reason_message = f"Reason: {reason} - Headers: {context['headers']}"

    return details, reason_message


def _build_log_message_generic(
    context: dict[str, Any], log_type: str, reason: str
) -> tuple[str, str]:
    message = f"{log_type.capitalize()} from"
    details = f"{message} {context['client_ip']}: {context['method']} {context['url']}"
    reason_message = f"Details: {reason} - Headers: {context['headers']}"
    return details, reason_message


async def _dispatch_block_hook(
    request: GuardRequest,
    log_type: str,
    check_name: str | None,
    reason: str,
    trigger_info: str,
    passive_mode: bool,
    on_block: Callable[[GuardRequest, dict[str, Any]], Any] | None,
    sensitive_params: frozenset[str] | None,
    sensitive_body_fields: frozenset[str] | None,
    sensitive_headers: frozenset[str] | None = None,
) -> None:
    if log_type != "suspicious":
        return
    if not passive_mode:
        request.state._guard_block_stash = {
            "reason": reason,
            "trigger_info": trigger_info,
        }
        return
    await fire_block_hook(
        on_block,
        request,
        check_name or "",
        reason,
        trigger_info,
        True,
        None,
        sensitive_params,
        sensitive_body_fields,
        sensitive_headers,
    )


async def log_activity(
    request: GuardRequest,
    logger: logging.Logger,
    log_type: str = "request",
    reason: str = "",
    passive_mode: bool = False,
    trigger_info: str = "",
    level: Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] | None = "WARNING",
    check_name: str | None = None,
    muted_check_logs: frozenset[str] | None = None,
    on_block: Callable[[GuardRequest, dict[str, Any]], Any] | None = None,
    sensitive_headers: frozenset[str] | None = None,
    sensitive_params: frozenset[str] | None = None,
    sensitive_body_fields: frozenset[str] | None = None,
) -> None:
    await _dispatch_block_hook(
        request,
        log_type,
        check_name,
        reason,
        trigger_info,
        passive_mode,
        on_block,
        sensitive_params,
        sensitive_body_fields,
        sensitive_headers,
    )
    if level is None:
        return
    if (
        check_name is not None
        and muted_check_logs is not None
        and check_name in muted_check_logs
    ):
        return

    context = _extract_request_context(
        request, sensitive_headers, sensitive_params, sensitive_body_fields
    )

    if log_type == "request":
        details, reason_message = _build_log_message_for_request(context)
    elif log_type == "suspicious":
        details, reason_message = _build_log_message_for_suspicious(
            context, reason, passive_mode, trigger_info
        )
    else:
        details, reason_message = _build_log_message_generic(context, log_type, reason)

    msg = f"{details} - {reason_message}"
    _log_at_level(logger, level, msg)
