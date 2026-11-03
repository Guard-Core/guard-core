import logging
from contextlib import ExitStack
from types import ModuleType
from unittest.mock import patch

import tests.test_sensitive_data_invariant as INV_ASYNC
import tests.test_sync.test_sensitive_data_invariant as INV_SYNC


class CaptureHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def clear(self) -> None:
        self.records = []

    def text(self) -> str:
        return "\n".join(r.getMessage() for r in self.records)


class FakeCaplog:
    def __init__(self, handler: CaptureHandler) -> None:
        self._handler = handler

    @property
    def records(self) -> list[logging.LogRecord]:
        return self._handler.records

    @property
    def text(self) -> str:
        return self._handler.text()


def reset_case_state(mod: ModuleType) -> None:
    mod._ON_BLOCK_CALLS.clear()
    mod._ON_ERROR_CALLS.clear()
    mod._LOGFIRE_CALLS.clear()
    mod._AGENT_RECORDER.events.clear()
    mod._AGENT_RECORDER.metrics.clear()
    mod._MIDDLEWARE.suspicious_request_counts.clear()
    if getattr(mod, "_otel_sdk_available", False) and mod._SPAN_EXPORTER is not None:
        mod._SPAN_EXPORTER.clear()
    mod.sus_patterns_handler.agent_handler = mod._AGENT_RECORDER


def _snippet(dump: str, secret: str, radius: int = 60) -> str:
    idx = dump.find(secret)
    if idx == -1:
        return ""
    start = max(0, idx - radius)
    end = min(len(dump), idx + len(secret) + radius)
    return dump[start:end]


def scan_all_channels(mod: ModuleType, secret: str) -> list[tuple[str, str]]:
    leaks: list[tuple[str, str]] = []
    events_dump = mod._events_dump(mod._AGENT_RECORDER.events)
    if secret in events_dump:
        leaks.append(("security_event", _snippet(events_dump, secret)))
    metrics_dump = mod._metrics_dump(mod._AGENT_RECORDER.metrics)
    if secret in metrics_dump:
        leaks.append(("security_metric", _snippet(metrics_dump, secret)))
    on_block_dump = mod._on_block_dump(mod._ON_BLOCK_CALLS)
    if secret in on_block_dump:
        leaks.append(("on_block", _snippet(on_block_dump, secret)))
    on_error_dump = mod._on_error_dump(mod._ON_ERROR_CALLS)
    if secret in on_error_dump:
        leaks.append(("on_error", _snippet(on_error_dump, secret)))
    logfire_dump = mod._logfire_dump(mod._LOGFIRE_CALLS)
    if secret in logfire_dump:
        leaks.append(("logfire", _snippet(logfire_dump, secret)))
    if getattr(mod, "_otel_sdk_available", False) and mod._SPAN_EXPORTER is not None:
        spans_dump = mod._spans_dump(mod._SPAN_EXPORTER)
        if secret in spans_dump:
            leaks.append(("otel_span", _snippet(spans_dump, secret)))
    return leaks


def logfire_patch_stack() -> ExitStack:
    stack = ExitStack()
    for logfire_module_path, span_cb, info_cb in (
        (
            "guard_core.core.events.logfire_handler",
            INV_ASYNC._record_logfire_span,
            INV_ASYNC._record_logfire_info,
        ),
        (
            "guard_core.sync.core.events.logfire_handler",
            INV_SYNC._record_logfire_span,
            INV_SYNC._record_logfire_info,
        ),
    ):
        stack.enter_context(patch(f"{logfire_module_path}._logfire_available", True))
        mock_logfire = stack.enter_context(patch(f"{logfire_module_path}.logfire"))
        mock_logfire.span.side_effect = span_cb
        mock_logfire.info.side_effect = info_cb
    return stack
