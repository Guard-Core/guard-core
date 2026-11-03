import logging
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest

import tests.test_sensitive_data_invariant as INV_ASYNC
import tests.test_sync.test_sensitive_data_invariant as INV_SYNC
from tests.redaction_gate.axes import (
    EXCLUDED_HEADER_NAME,
    SOFT_SEPARATORS,
    case_id_for,
    secret_for,
    variant_for_surface,
)
from tests.redaction_gate.blob import build_blob
from tests.redaction_gate.capture import (
    CaptureHandler,
    FakeCaplog,
    reset_case_state,
    scan_all_channels,
)
from tests.redaction_gate.surfaces import (
    build_async_request_for_surface,
    build_sync_request_for_surface,
)


@dataclass
class CaseResult:
    case_id: str
    phase: str
    surface: str | None
    axes: dict[str, Any] | None
    config_variant: str | None
    secret: str
    detected: bool
    outcome: str
    leaks: list[tuple[str, str]] = field(default_factory=list)


def classify(
    detected: bool, leaks: list[tuple[str, str]], unassigned_token: bool = False
) -> str:
    if leaks:
        return "UNASSIGNED_TOKEN" if unassigned_token else "LEAK"
    if not detected:
        return "NOT_DETECTED"
    return "OK"


def is_unassigned_token_case(axes: dict[str, Any]) -> bool:
    return (
        axes["value_mode"] == "empty_split" and axes["separator"] not in SOFT_SEPARATORS
    )


def build_module_variants(mod: ModuleType) -> dict[str, tuple[Any, Any, Any]]:
    variants: dict[str, tuple[Any, Any, Any]] = {
        "default": (mod._CONFIG, mod._MIDDLEWARE, mod._PIPELINE)
    }
    for name, overrides in (
        ("passive", {"passive_mode": True}),
        ("debug_level", {"log_suspicious_level": "DEBUG"}),
        ("excluded_header", {"excluded_detection_headers": {EXCLUDED_HEADER_NAME}}),
    ):
        cfg = mod._build_config(**overrides)
        mw = mod._build_middleware(cfg)
        pipeline = mod.build_default_pipeline(mw)
        variants[name] = (cfg, mw, pipeline)
    return variants


_client_ip_counter = 0


def next_client_ip() -> str:
    global _client_ip_counter
    _client_ip_counter = (_client_ip_counter + 1) % 65000
    a, b = divmod(_client_ip_counter, 250)
    return f"198.51.{100 + a % 100}.{1 + b}"


def _log_line_leak(capture: CaptureHandler, secret: str) -> list[tuple[str, str]]:
    log_text = capture.text()
    if secret not in log_text:
        return []
    line = next((ln for ln in log_text.splitlines() if secret in ln), log_text)
    return [("log_line", line)]


async def run_grammar_case(
    surface: str,
    axes: dict[str, Any],
    async_variants: dict[str, tuple[Any, Any, Any]],
    sync_variants: dict[str, tuple[Any, Any, Any]],
    capture: CaptureHandler,
) -> CaseResult:
    case_id = case_id_for(surface, axes)
    secret = secret_for(case_id, axes)
    variant_name = variant_for_surface(surface)
    async_cfg, _async_mw, async_pipeline = async_variants[variant_name]
    sync_cfg, _sync_mw, sync_pipeline = sync_variants[variant_name]

    reset_case_state(INV_ASYNC)
    reset_case_state(INV_SYNC)
    capture.clear()

    blob = build_blob(axes, secret)

    async_detect_req = build_async_request_for_surface(surface, blob)
    sync_detect_req = build_sync_request_for_surface(surface, blob)
    detection_async = await INV_ASYNC.detect_penetration_attempt(
        async_detect_req, async_cfg
    )
    detection_sync = INV_SYNC.detect_penetration_attempt(sync_detect_req, sync_cfg)

    async_pipe_req = build_async_request_for_surface(surface, blob)
    async_pipe_req.state.client_ip = next_client_ip()
    async_pipe_req.state.route_config = None
    pipeline_response_async = await async_pipeline.execute(async_pipe_req)

    sync_pipe_req = build_sync_request_for_surface(surface, blob)
    sync_pipe_req.state.client_ip = next_client_ip()
    sync_pipe_req.state.route_config = None
    pipeline_response_sync = sync_pipeline.execute(sync_pipe_req)

    leaks = _log_line_leak(capture, secret)
    leaks += [
        (f"async.{ch}", snip) for ch, snip in scan_all_channels(INV_ASYNC, secret)
    ]
    leaks += [(f"sync.{ch}", snip) for ch, snip in scan_all_channels(INV_SYNC, secret)]

    detected = bool(
        detection_async.is_threat
        or detection_sync.is_threat
        or pipeline_response_async is not None
        or pipeline_response_sync is not None
    )
    outcome = classify(detected, leaks, is_unassigned_token_case(axes))
    return CaseResult(
        case_id=case_id,
        phase="grammar",
        surface=surface,
        axes=dict(axes),
        config_variant=variant_name,
        secret=secret,
        detected=detected,
        outcome=outcome,
        leaks=leaks,
    )


async def run_fixed_case_async(
    case: INV_ASYNC.Case, capture: CaptureHandler
) -> CaseResult:
    secret = f"SECRET-fixedA-{case.id}"
    reset_case_state(INV_ASYNC)
    capture.clear()
    logger = logging.getLogger("guard_core.genprobe.fixed.async")
    cfg = INV_ASYNC._CONFIG

    request = case.request_factory(secret)
    detection_result = await INV_ASYNC.detect_penetration_attempt(request, cfg)

    await INV_ASYNC.log_activity(
        request,
        logger,
        log_type="request",
        level="INFO",
        sensitive_headers=cfg.log_sensitive_headers,
        sensitive_params=cfg.log_sensitive_params,
        sensitive_body_fields=cfg.log_sensitive_body_fields,
    )
    await INV_ASYNC.log_activity(
        request,
        logger,
        log_type="suspicious",
        passive_mode=False,
        reason=f"Suspicious activity detected: {detection_result.trigger_info}",
        trigger_info=detection_result.trigger_info,
        level="WARNING",
        on_block=INV_ASYNC._record_on_block,
        sensitive_headers=cfg.log_sensitive_headers,
        sensitive_params=cfg.log_sensitive_params,
        sensitive_body_fields=cfg.log_sensitive_body_fields,
    )
    await INV_ASYNC.log_activity(
        request,
        logger,
        log_type="suspicious",
        passive_mode=True,
        trigger_info=detection_result.trigger_info,
        level="WARNING",
        on_block=INV_ASYNC._record_on_block,
        sensitive_headers=cfg.log_sensitive_headers,
        sensitive_params=cfg.log_sensitive_params,
        sensitive_body_fields=cfg.log_sensitive_body_fields,
    )
    await INV_ASYNC.log_activity(
        request,
        logger,
        log_type="generic",
        reason=f"Generic event: {detection_result.trigger_info}",
        level="WARNING",
        sensitive_headers=cfg.log_sensitive_headers,
        sensitive_params=cfg.log_sensitive_params,
        sensitive_body_fields=cfg.log_sensitive_body_fields,
    )

    pipeline_request = case.request_factory(secret)
    pipeline_request.state.client_ip = next_client_ip()
    pipeline_request.state.route_config = None
    pipeline_response = await INV_ASYNC._PIPELINE.execute(pipeline_request)

    leaks = _log_line_leak(capture, secret)
    leaks += [
        (f"async.{ch}", snip) for ch, snip in scan_all_channels(INV_ASYNC, secret)
    ]

    detected = bool(detection_result.is_threat or pipeline_response is not None)
    return CaseResult(
        case_id=f"fixed_async::{case.id}",
        phase="fixed_async",
        surface=None,
        axes=None,
        config_variant="default",
        secret=secret,
        detected=detected,
        outcome=classify(detected, leaks),
        leaks=leaks,
    )


def run_fixed_case_sync(case: INV_SYNC.Case, capture: CaptureHandler) -> CaseResult:
    secret = f"SECRET-fixedS-{case.id}"
    reset_case_state(INV_SYNC)
    capture.clear()
    logger = logging.getLogger("guard_core.genprobe.fixed.sync")
    cfg = INV_SYNC._CONFIG

    request = case.request_factory(secret)
    detection_result = INV_SYNC.detect_penetration_attempt(request, cfg)

    INV_SYNC.log_activity(
        request,
        logger,
        log_type="request",
        level="INFO",
        sensitive_headers=cfg.log_sensitive_headers,
        sensitive_params=cfg.log_sensitive_params,
        sensitive_body_fields=cfg.log_sensitive_body_fields,
    )
    INV_SYNC.log_activity(
        request,
        logger,
        log_type="suspicious",
        passive_mode=False,
        reason=f"Suspicious activity detected: {detection_result.trigger_info}",
        trigger_info=detection_result.trigger_info,
        level="WARNING",
        on_block=INV_SYNC._record_on_block,
        sensitive_headers=cfg.log_sensitive_headers,
        sensitive_params=cfg.log_sensitive_params,
        sensitive_body_fields=cfg.log_sensitive_body_fields,
    )
    INV_SYNC.log_activity(
        request,
        logger,
        log_type="suspicious",
        passive_mode=True,
        trigger_info=detection_result.trigger_info,
        level="WARNING",
        on_block=INV_SYNC._record_on_block,
        sensitive_headers=cfg.log_sensitive_headers,
        sensitive_params=cfg.log_sensitive_params,
        sensitive_body_fields=cfg.log_sensitive_body_fields,
    )
    INV_SYNC.log_activity(
        request,
        logger,
        log_type="generic",
        reason=f"Generic event: {detection_result.trigger_info}",
        level="WARNING",
        sensitive_headers=cfg.log_sensitive_headers,
        sensitive_params=cfg.log_sensitive_params,
        sensitive_body_fields=cfg.log_sensitive_body_fields,
    )

    pipeline_request = case.request_factory(secret)
    pipeline_request.state.client_ip = next_client_ip()
    pipeline_request.state.route_config = None
    pipeline_response = INV_SYNC._PIPELINE.execute(pipeline_request)

    leaks = _log_line_leak(capture, secret)
    leaks += [(f"sync.{ch}", snip) for ch, snip in scan_all_channels(INV_SYNC, secret)]

    detected = bool(detection_result.is_threat or pipeline_response is not None)
    return CaseResult(
        case_id=f"fixed_sync::{case.id}",
        phase="fixed_sync",
        surface=None,
        axes=None,
        config_variant="default",
        secret=secret,
        detected=detected,
        outcome=classify(detected, leaks),
        leaks=leaks,
    )


async def run_component_scenario_async(
    scenario: INV_ASYNC.ComponentScenario, capture: CaptureHandler, tmp_dir: Path
) -> CaseResult:
    secret = f"SECRET-componentA-{scenario.id}"
    reset_case_state(INV_ASYNC)
    capture.clear()
    ctx = INV_ASYNC._ScenarioContext(
        caplog=cast(pytest.LogCaptureFixture, FakeCaplog(capture)), tmp_path=tmp_dir
    )
    try:
        await scenario.run(secret, ctx)
        errored = False
    except Exception:
        errored = True

    leaks = _log_line_leak(capture, secret)
    leaks += [
        (f"async.{ch}", snip) for ch, snip in scan_all_channels(INV_ASYNC, secret)
    ]

    outcome = "ERROR" if errored else classify(True, leaks)
    return CaseResult(
        case_id=f"component_async::{scenario.id}",
        phase="component_async",
        surface=None,
        axes=None,
        config_variant=None,
        secret=secret,
        detected=True,
        outcome=outcome,
        leaks=leaks,
    )


def run_component_scenario_sync(
    scenario: INV_SYNC.ComponentScenario, capture: CaptureHandler, tmp_dir: Path
) -> CaseResult:
    secret = f"SECRET-componentS-{scenario.id}"
    reset_case_state(INV_SYNC)
    capture.clear()
    ctx = INV_SYNC._ScenarioContext(
        caplog=cast(pytest.LogCaptureFixture, FakeCaplog(capture)), tmp_path=tmp_dir
    )
    try:
        scenario.run(secret, ctx)
        errored = False
    except Exception:
        errored = True

    leaks = _log_line_leak(capture, secret)
    leaks += [(f"sync.{ch}", snip) for ch, snip in scan_all_channels(INV_SYNC, secret)]

    outcome = "ERROR" if errored else classify(True, leaks)
    return CaseResult(
        case_id=f"component_sync::{scenario.id}",
        phase="component_sync",
        surface=None,
        axes=None,
        config_variant=None,
        secret=secret,
        detected=True,
        outcome=outcome,
        leaks=leaks,
    )
