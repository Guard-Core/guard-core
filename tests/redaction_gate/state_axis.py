from types import ModuleType
from typing import Any, TypeVar

import tests.test_sensitive_data_invariant as INV_ASYNC
import tests.test_sync.test_sensitive_data_invariant as INV_SYNC
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.sync.core.checks.pipeline import (
    SecurityCheckPipeline as SyncSecurityCheckPipeline,
)
from tests.conftest import MockGuardRequest
from tests.redaction_gate.axes import BASELINE_AXES
from tests.redaction_gate.blob import build_blob
from tests.redaction_gate.capture import (
    CaptureHandler,
    reset_case_state,
    scan_all_channels,
)
from tests.redaction_gate.runner import CaseResult, classify, next_client_ip
from tests.redaction_gate.surfaces import (
    build_async_request_for_surface,
    build_sync_request_for_surface,
)
from tests.test_sync.conftest import SyncMockGuardRequest

STATES = [
    "rate_limited",
    "banned",
    "emergency",
    "cloud_blocked",
    "country_blocked",
    "time_window",
    "request_logged",
]

STATE_SURFACES = ["header", "query_param", "json_shallow"]

_RequestT = TypeVar("_RequestT", MockGuardRequest, SyncMockGuardRequest)

_TIME_RESTRICTIONS = {"start": "00:00", "end": "00:01", "timezone": "UTC"}

_CLOUD_HANDLER_PATCH_TARGETS = {
    False: "guard_core.handlers.cloud_handler.cloud_handler",
    True: "guard_core.sync.handlers.cloud_handler.cloud_handler",
}


def _log_line_leak(capture: CaptureHandler, secret: str) -> list[tuple[str, str]]:
    log_text = capture.text()
    if secret not in log_text:
        return []
    line = next((ln for ln in log_text.splitlines() if secret in ln), log_text)
    return [("log_line", line)]


def _build_rate_limited(mod: ModuleType) -> tuple[Any, Any]:
    config = mod._scenario_config(
        enable_rate_limiting=True, rate_limit=1, rate_limit_window=60
    )
    return config, mod._scenario_middleware(config)


def _build_banned(mod: ModuleType) -> tuple[Any, Any]:
    config = mod._scenario_config()
    return config, mod._scenario_middleware(config)


def _build_emergency(mod: ModuleType) -> tuple[Any, Any]:
    config = mod._scenario_config(emergency_mode=True, emergency_whitelist=[])
    return config, mod._scenario_middleware(config)


def _build_cloud_blocked(mod: ModuleType) -> tuple[Any, Any]:
    config = mod._scenario_config(block_cloud_providers=frozenset({"AWS"}))
    return config, mod._scenario_middleware(config)


def _build_country_blocked(mod: ModuleType) -> tuple[Any, Any]:
    geo_ip_handler = mod.MagicMock()
    geo_ip_handler.get_country = mod.MagicMock(return_value="XX")
    config = mod._scenario_config(
        blocked_countries=frozenset({"XX"}), geo_ip_handler=geo_ip_handler
    )
    return config, mod._scenario_middleware(config, geo_ip_handler=geo_ip_handler)


def _build_time_window(mod: ModuleType) -> tuple[Any, Any]:
    config = mod._scenario_config()
    return config, mod._scenario_middleware(config)


def _build_request_logged(mod: ModuleType) -> tuple[Any, Any]:
    config = mod._scenario_config(log_request_level="INFO")
    return config, mod._scenario_middleware(config)


_STATE_BUILDERS = {
    "rate_limited": _build_rate_limited,
    "banned": _build_banned,
    "emergency": _build_emergency,
    "cloud_blocked": _build_cloud_blocked,
    "country_blocked": _build_country_blocked,
    "time_window": _build_time_window,
    "request_logged": _build_request_logged,
}


def _patch_time_window_check(
    pipeline: SecurityCheckPipeline | SyncSecurityCheckPipeline,
    mod: ModuleType,
    *,
    is_sync: bool,
) -> None:
    time_window_check = next(
        c for c in pipeline.checks if c.check_name == "time_window"
    )
    if is_sync:
        vars(time_window_check)["_check_time_window"] = lambda _time_restrictions: False
    else:
        vars(time_window_check)["_check_time_window"] = mod.AsyncMock(
            return_value=False
        )


def build_state_variant(
    mod: ModuleType, state: str, *, is_sync: bool
) -> tuple[Any, Any, SecurityCheckPipeline | SyncSecurityCheckPipeline]:
    builder = _STATE_BUILDERS.get(state)
    if builder is None:
        raise ValueError(f"unknown state {state!r}")
    config, middleware = builder(mod)
    pipeline = mod.build_default_pipeline(middleware)
    if state == "time_window":
        _patch_time_window_check(pipeline, mod, is_sync=is_sync)
    return config, middleware, pipeline


def _prepare_request_for_case(
    request: _RequestT, mod: ModuleType, state: str, client_ip: str
) -> _RequestT:
    request.state.client_ip = client_ip
    request.state.route_config = None
    if state == "time_window":
        route_config = mod.RouteConfig()
        route_config.time_restrictions = dict(_TIME_RESTRICTIONS)
        request.state.route_config = route_config
    return request


async def run_state_case_async(
    state: str, surface: str, pipeline: SecurityCheckPipeline, capture: CaptureHandler
) -> CaseResult:
    mod = INV_ASYNC
    secret = f"SECRET-state.{state}.{surface}"
    reset_case_state(mod)
    capture.clear()
    client_ip = next_client_ip()

    if state == "rate_limited":
        primer = mod._header_request("X-Primer", "warmup")
        primer.state.client_ip = client_ip
        primer.state.route_config = None
        await pipeline.execute(primer)
    elif state == "banned":
        await mod.ip_ban_manager.ban_ip(client_ip, 300, "state_axis")

    blob = build_blob(BASELINE_AXES, secret)
    request = _prepare_request_for_case(
        build_async_request_for_surface(surface, blob), mod, state, client_ip
    )
    await pipeline.execute(request)

    leaks = _log_line_leak(capture, secret)
    leaks += [(f"async.{ch}", snip) for ch, snip in scan_all_channels(mod, secret)]
    return CaseResult(
        case_id=f"state_async::{state}::{surface}",
        phase="state_async",
        surface=surface,
        axes={"state": state},
        config_variant=state,
        secret=secret,
        detected=True,
        outcome=classify(True, leaks),
        leaks=leaks,
    )


def run_state_case_sync(
    state: str,
    surface: str,
    pipeline: SyncSecurityCheckPipeline,
    capture: CaptureHandler,
) -> CaseResult:
    mod = INV_SYNC
    secret = f"SECRET-state.{state}.{surface}"
    reset_case_state(mod)
    capture.clear()
    client_ip = next_client_ip()

    if state == "rate_limited":
        primer = mod._header_request("X-Primer", "warmup")
        primer.state.client_ip = client_ip
        primer.state.route_config = None
        pipeline.execute(primer)
    elif state == "banned":
        mod.ip_ban_manager.ban_ip(client_ip, 300, "state_axis")

    blob = build_blob(BASELINE_AXES, secret)
    request = _prepare_request_for_case(
        build_sync_request_for_surface(surface, blob), mod, state, client_ip
    )
    pipeline.execute(request)

    leaks = _log_line_leak(capture, secret)
    leaks += [(f"sync.{ch}", snip) for ch, snip in scan_all_channels(mod, secret)]
    return CaseResult(
        case_id=f"state_sync::{state}::{surface}",
        phase="state_sync",
        surface=surface,
        axes={"state": state},
        config_variant=state,
        secret=secret,
        detected=True,
        outcome=classify(True, leaks),
        leaks=leaks,
    )


async def run_state_phase(capture: CaptureHandler) -> list[CaseResult]:
    print(
        "running state-axis replay (rate_limited/banned/emergency/cloud_blocked/"
        "country_blocked/time_window/request_logged)..."
    )
    results: list[CaseResult] = []
    for state in STATES:
        async_config, async_middleware, async_pipeline = build_state_variant(
            INV_ASYNC, state, is_sync=False
        )
        sync_config, sync_middleware, sync_pipeline = build_state_variant(
            INV_SYNC, state, is_sync=True
        )
        assert isinstance(async_pipeline, SecurityCheckPipeline)
        assert isinstance(sync_pipeline, SyncSecurityCheckPipeline)
        cloud_patches = []
        if state == "cloud_blocked":
            for is_sync, target in _CLOUD_HANDLER_PATCH_TARGETS.items():
                mod = INV_SYNC if is_sync else INV_ASYNC
                is_cloud_ip = mod.patch(f"{target}.is_cloud_ip", return_value=True)
                details = mod.patch(
                    f"{target}.get_cloud_provider_details",
                    return_value=("AWS", "1.2.3.0/24"),
                )
                is_cloud_ip.start()
                details.start()
                cloud_patches.extend([is_cloud_ip, details])
        try:
            for surface in STATE_SURFACES:
                results.append(
                    await run_state_case_async(state, surface, async_pipeline, capture)
                )
                results.append(
                    run_state_case_sync(state, surface, sync_pipeline, capture)
                )
        finally:
            for p in cloud_patches:
                p.stop()
    print(f"  state-axis replay done: {len(results)} cases")
    return results
