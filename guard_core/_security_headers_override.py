"""The cross-app override that a call to the global ``configure()`` sets.

A call sets exactly the keys it passes. Those keys override the
``security_headers`` config of every guarded app in the process (and, with
Redis, in every worker that runs the same startup config); the keys it does not
pass are not overridden. The pure parts live here so the async tree and its sync
mirror share one copy.
"""

import hashlib
import json
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from guard_core._security_headers_defaults import SECURITY_HEADER_NAMES

OVERRIDE_PULL_INTERVAL_SECONDS = 5.0
MAX_CLOCK_SKEW_SECONDS = 86400.0
PERMISSIONS_POLICY_NOT_PASSED = "UNSET"


class _NotPassed:
    def __repr__(self) -> str:
        return "NOT_PASSED"

    def __bool__(self) -> bool:
        return False


NOT_PASSED = _NotPassed()


def passed_or(value: Any, default: Any) -> Any:
    return default if isinstance(value, _NotPassed) else value


def now_monotonic() -> float:
    return time.monotonic()


def wall_now() -> float:
    return time.time()


def corrected_wall_now() -> float:
    # The local wall clock moved onto Redis time by the offset the worker measured.
    return wall_now() + PROCESS_OVERRIDE.clock_offset


_WALL_ANCHOR = time.time()
_MONOTONIC_ANCHOR = time.monotonic()


def approximate_now() -> float:
    # Wall time without calling time.time(): the wall clock at import plus the
    # monotonic time elapsed since, so a clock that jumps or is frozen does not move it.
    return _WALL_ANCHOR + (time.monotonic() - _MONOTONIC_ANCHOR)


@dataclass(frozen=True)
class OverrideRecord:
    set_at: float
    keys: Mapping[str, Any]
    event: Mapping[str, Any] | None = field(default=None, compare=False)

    def ordered_at(self) -> float:
        # A record stamped further ahead than any plausible clock skew (a clock
        # that jumped forward, or a frozen one) must not outrank every later call.
        corrected = approximate_now() + PROCESS_OVERRIDE.clock_offset
        if self.set_at > corrected + MAX_CLOCK_SKEW_SECONDS:
            return 0.0
        return self.set_at

    def to_json(self) -> str:
        return json.dumps({"set_at": self.set_at, "keys": dict(self.keys)})

    @classmethod
    def from_json(cls, raw: str | bytes) -> "OverrideRecord":
        data = json.loads(raw)
        keys = data["keys"]
        if not isinstance(keys, dict):
            raise ValueError("override keys must be an object")
        return cls(float(data["set_at"]), keys)


class _ProcessOverride:
    def __init__(self) -> None:
        self.record = OverrideRecord(0.0, {})
        self.reset_epoch = 0
        self.clock_offset = 0.0


PROCESS_OVERRIDE = _ProcessOverride()


def override_from_call(
    *,
    enabled: Any,
    csp: Any,
    hsts_max_age: Any,
    hsts_include_subdomains: Any,
    hsts_preload: Any,
    frame_options: Any,
    content_type_options: Any,
    xss_protection: Any,
    referrer_policy: Any,
    permissions_policy: Any,
    custom_headers: Any,
) -> dict[str, Any]:
    passed: dict[str, Any] = {}
    for key, value in (
        ("enabled", enabled),
        ("csp", csp),
        ("frame_options", frame_options),
        ("content_type_options", content_type_options),
        ("xss_protection", xss_protection),
        ("referrer_policy", referrer_policy),
        ("custom", custom_headers),
    ):
        if value is not NOT_PASSED:
            passed[key] = value
    if permissions_policy != PERMISSIONS_POLICY_NOT_PASSED:
        passed["permissions_policy"] = permissions_policy
    hsts = _hsts_from_call(hsts_max_age, hsts_include_subdomains, hsts_preload)
    if hsts is not NOT_PASSED:
        passed["hsts"] = hsts
    return passed


def _hsts_from_call(max_age: Any, include_subdomains: Any, preload: Any) -> Any:
    if max_age is None:
        return None
    sub_keys = {
        key: value
        for key, value in (
            ("max_age", max_age),
            ("include_subdomains", include_subdomains),
            ("preload", preload),
        )
        if value is not NOT_PASSED
    }
    return sub_keys or NOT_PASSED


def apply_override(
    effective: dict[str, Any], override: Mapping[str, Any]
) -> dict[str, Any]:
    merged = dict(effective)
    for key, value in override.items():
        current = merged.get(key)
        if key == "hsts" and isinstance(value, dict) and isinstance(current, dict):
            merged[key] = {**current, **value}
        else:
            merged[key] = value
    return merged


def override_fingerprint(override: Mapping[str, Any]) -> str:
    if not override:
        return ""
    content = json.dumps(override, sort_keys=True, default=str)
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def _stable(value: Any) -> Any:
    if isinstance(value, (set, frozenset)):
        return sorted(str(item) for item in value)
    if callable(value):
        name = getattr(value, "__qualname__", type(value).__name__)
        return f"{getattr(value, '__module__', '')}.{name}"
    return f"<{type(value).__module__}.{type(value).__qualname__}>"


def config_fingerprint(config: Any) -> str:
    content = json.dumps(
        config.model_dump(mode="python"), sort_keys=True, default=_stable
    )
    return hashlib.sha256(content.encode()).hexdigest()[:32]


def _display_value(value: Any) -> str:
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True, default=str)
    return str(value)


def override_display(keys: Mapping[str, Any]) -> dict[str, str]:
    shown: dict[str, str] = {}
    for key, value in keys.items():
        if key == "custom" and isinstance(value, dict):
            shown.update(
                {str(name): _display_value(item) for name, item in value.items()}
            )
        elif key == "csp":
            shown["Content-Security-Policy"] = _display_value(value)
        elif key == "hsts":
            shown["Strict-Transport-Security"] = _display_value(value)
        else:
            shown[SECURITY_HEADER_NAMES.get(key, key)] = _display_value(value)
    return shown


def override_event_metadata(
    keys: Iterable[str],
    dropped: Iterable[str],
    values: Mapping[str, str],
    dropped_values: Mapping[str, str],
) -> dict[str, Any]:
    return {
        "override_keys": sorted(keys),
        "dropped_keys": sorted(dropped),
        "override_values": dict(values),
        "dropped_values": dict(dropped_values),
    }
