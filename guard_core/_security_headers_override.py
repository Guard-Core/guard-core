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
from collections.abc import Callable, Iterable, Mapping
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

# The newest record any manager of this process pulled from Redis, by startup-config
# hash. A component that never pulls (CorsHandler's manager) reads its override here.
PULLED_OVERRIDES: dict[str, OverrideRecord] = {}

# (config id, override time) pairs whose CORS effect was already logged or sent.
CORS_LOGGED: dict[tuple[int, float], None] = {}
CORS_EVENTED: dict[tuple[int, float], None] = {}
MAX_CORS_NOTES = 1024


def first_time(seen: dict[tuple[int, float], None], key: tuple[int, float]) -> bool:
    if key in seen:
        return False
    if len(seen) >= MAX_CORS_NOTES:
        seen.pop(next(iter(seen)))
    seen[key] = None
    return True


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
    enable_cors: Any = NOT_PASSED,
    cors_origins: Any = NOT_PASSED,
    cors_allow_credentials: Any = NOT_PASSED,
    cors_allow_methods: Any = NOT_PASSED,
    cors_allow_headers: Any = NOT_PASSED,
    cors_max_age: Any = NOT_PASSED,
    cors_expose_headers: Any = NOT_PASSED,
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
        ("enable_cors", enable_cors),
        ("cors_origins", cors_origins),
        ("cors_allow_credentials", cors_allow_credentials),
        ("cors_allow_methods", cors_allow_methods),
        ("cors_allow_headers", cors_allow_headers),
        ("cors_max_age", cors_max_age),
        ("cors_expose_headers", cors_expose_headers),
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


CORS_OVERRIDE_KEYS = frozenset(
    {
        "enable_cors",
        "cors_origins",
        "cors_allow_credentials",
        "cors_allow_methods",
        "cors_allow_headers",
        "cors_max_age",
        "cors_expose_headers",
    }
)


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _is_bool(value: Any) -> bool:
    return isinstance(value, bool)


def _is_seconds(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


_CORS_RULES: dict[str, tuple[Callable[[Any], bool], str]] = {
    "cors_origins": (_is_string_list, "a list of strings"),
    "cors_allow_methods": (_is_string_list, "a list of strings"),
    "cors_allow_headers": (_is_string_list, "a list of strings"),
    "cors_expose_headers": (_is_string_list, "a list of strings"),
    "enable_cors": (_is_bool, "a bool"),
    "cors_allow_credentials": (_is_bool, "a bool"),
    "cors_max_age": (_is_seconds, "a non-negative integer"),
}


def validate_cors_override(keys: Mapping[str, Any]) -> None:
    for name, (valid, expected) in _CORS_RULES.items():
        if name in keys and not valid(keys[name]):
            raise ValueError(f"{name} must be {expected}")


@dataclass(frozen=True)
class CorsParams:
    enabled: bool
    origins: tuple[str, ...]
    credentials: bool
    methods: tuple[str, ...]
    headers: tuple[str, ...]
    max_age: int
    expose: tuple[str, ...]


def cors_params_of(config: Any) -> CorsParams:
    return CorsParams(
        enabled=bool(config.enable_cors),
        origins=tuple(config.cors_allow_origins or ()),
        credentials=bool(config.cors_allow_credentials),
        methods=tuple(config.cors_allow_methods or ()),
        headers=tuple(config.cors_allow_headers or ()),
        max_age=int(config.cors_max_age),
        expose=tuple(config.cors_expose_headers or ()),
    )


def merge_cors(
    base: CorsParams, keys: Mapping[str, Any]
) -> tuple[CorsParams, str | None]:
    """The app's CORS with the override's passed keys applied, and why it was refused.

    A merge that would be a wildcard origin with credentials is refused: the app
    keeps its own CORS and the reason is returned.
    """
    if not CORS_OVERRIDE_KEYS & keys.keys():
        return base, None
    merged = CorsParams(
        enabled=keys.get("enable_cors", base.enabled),
        origins=tuple(keys.get("cors_origins", base.origins)),
        credentials=keys.get("cors_allow_credentials", base.credentials),
        methods=tuple(keys.get("cors_allow_methods", base.methods)),
        headers=tuple(keys.get("cors_allow_headers", base.headers)),
        max_age=keys.get("cors_max_age", base.max_age),
        expose=tuple(keys.get("cors_expose_headers", base.expose)),
    )
    if merged.enabled and "*" in merged.origins and merged.credentials:
        return base, "a wildcard origin cannot be combined with credentials"
    return merged, None


def cors_widens(base: CorsParams, merged: CorsParams) -> bool:
    if not merged.enabled:
        return False
    if not base.enabled:
        return True
    added = (
        set(merged.origins) - set(base.origins),
        {m.upper() for m in merged.methods} - {m.upper() for m in base.methods},
        {h.lower() for h in merged.headers} - {h.lower() for h in base.headers},
    )
    return (merged.credentials and not base.credentials) or any(added)
