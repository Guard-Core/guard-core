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
from typing import Protocol, TypeVar

from guard_core._lazy_patterns import LazyPatterns, module_attribute_lookup
from guard_core._security_headers_defaults import (
    SECURITY_HEADER_NAMES,
    security_headers_are_off,
)
from guard_core._security_headers_value_checks import (
    _is_string_list as _is_string_list,
)
from guard_core._security_headers_value_checks import (
    _require_resolvable_override_keys,
    require_clean_csp_directive,
    require_valid_hsts_max_age,
)

OVERRIDE_PULL_INTERVAL_SECONDS = 5.0
MAX_CLOCK_SKEW_SECONDS = 86400.0
PERMISSIONS_POLICY_NOT_PASSED = "UNSET"


class _NotPassed:
    def __repr__(self) -> str:
        return "NOT_PASSED"

    def __bool__(self) -> bool:
        return False


NOT_PASSED = _NotPassed()


_Value = TypeVar("_Value")
_Default = TypeVar("_Default")


def passed_or(value: _Value | _NotPassed, default: _Default) -> _Value | _Default:
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
    keys: Mapping[str, object]
    event: Mapping[str, object] | None = field(default=None, compare=False)

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
        _require_resolvable_override_keys(keys)
        validate_cors_override(keys)
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
    enabled: bool | _NotPassed,
    csp: dict[str, list[str]] | None | _NotPassed,
    hsts_max_age: int | None | _NotPassed,
    hsts_include_subdomains: bool | _NotPassed,
    hsts_preload: bool | _NotPassed,
    frame_options: str | None | _NotPassed,
    content_type_options: str | None | _NotPassed,
    xss_protection: str | None | _NotPassed,
    referrer_policy: str | None | _NotPassed,
    permissions_policy: str | None,
    custom_headers: dict[str, str] | None | _NotPassed,
    enable_cors: bool | _NotPassed = NOT_PASSED,
    cors_origins: list[str] | None | _NotPassed = NOT_PASSED,
    cors_allow_credentials: bool | _NotPassed = NOT_PASSED,
    cors_allow_methods: list[str] | None | _NotPassed = NOT_PASSED,
    cors_allow_headers: list[str] | None | _NotPassed = NOT_PASSED,
    cors_max_age: int | None | _NotPassed = NOT_PASSED,
    cors_expose_headers: list[str] | None | _NotPassed = NOT_PASSED,
) -> dict[str, object]:
    passed: dict[str, object] = {}
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


def _hsts_from_call(
    max_age: int | None | _NotPassed,
    include_subdomains: bool | _NotPassed,
    preload: bool | _NotPassed,
) -> dict[str, object] | None | _NotPassed:
    if max_age is None:
        return None
    sub_keys: dict[str, object] = {
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
    effective: Mapping[str, object], override: Mapping[str, object]
) -> dict[str, object]:
    merged = dict(effective)
    for key, value in override.items():
        current = merged.get(key)
        if key == "hsts" and isinstance(value, dict) and isinstance(current, dict):
            merged[key] = {**current, **value}
        else:
            merged[key] = value
    return merged


def override_fingerprint(override: Mapping[str, object]) -> str:
    if not override:
        return ""
    content = json.dumps(override, sort_keys=True, default=str)
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def _stable(value: object) -> list[str] | str:
    if isinstance(value, (set, frozenset)):
        return sorted(str(item) for item in value)
    if callable(value):
        name = getattr(value, "__qualname__", type(value).__name__)
        return f"{getattr(value, '__module__', '')}.{name}"
    return f"<{type(value).__module__}.{type(value).__qualname__}>"


class ModelDumpable(Protocol):
    def model_dump(self, *, mode: str) -> Mapping[str, object]: ...


def config_fingerprint(config: ModelDumpable) -> str:
    content = json.dumps(
        config.model_dump(mode="python"), sort_keys=True, default=_stable
    )
    return hashlib.sha256(content.encode()).hexdigest()[:32]


def _display_value(value: object) -> str:
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True, default=str)
    return str(value)


def override_display(keys: Mapping[str, object]) -> dict[str, str]:
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
) -> dict[str, object]:
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


def _is_bool(value: object) -> bool:
    return isinstance(value, bool)


def _is_seconds(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


_CORS_RULES: dict[str, tuple[Callable[[object], bool], str]] = {
    "cors_origins": (_is_string_list, "a list of strings"),
    "cors_allow_methods": (_is_string_list, "a list of strings"),
    "cors_allow_headers": (_is_string_list, "a list of strings"),
    "cors_expose_headers": (_is_string_list, "a list of strings"),
    "enable_cors": (_is_bool, "a bool"),
    "cors_allow_credentials": (_is_bool, "a bool"),
    "cors_max_age": (_is_seconds, "a non-negative integer"),
}


def validate_cors_override(keys: Mapping[str, object]) -> None:
    for name, (valid, expected) in _CORS_RULES.items():
        if name in keys and not valid(keys[name]):
            raise ValueError(f"{name} must be {expected}")


def has_control_character(value: str) -> bool:
    return _PATTERNS["_CONTROL_CHARACTER_RE"].search(value) is not None


def is_clean_cors_value(value: str) -> bool:
    return not has_control_character(value)


def is_http_token(value: str) -> bool:
    return _PATTERNS["_HTTP_TOKEN_RE"].fullmatch(value) is not None


_PATTERNS = LazyPatterns(
    {
        "_ORIGIN_TOKEN_RE": (
            r"(?:\*|null|[A-Za-z][A-Za-z0-9+.-]*://[^\s/?#@\\\x00-\x1f\x7f]+/?)",
            0,
        ),
        "_CONTROL_CHARACTER_RE": (r"[\x00-\x1f\x7f]", 0),
        "_HTTP_TOKEN_RE": (r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", 0),
        "_HEADER_VALUE_FORBIDDEN_RE": (r"[^\t\x20-\x7e\x80-\xff]", 0),
    }
)
__getattr__ = module_attribute_lookup(_PATTERNS)


def checked_header_name(name: str) -> str:
    if not is_http_token(name):
        raise ValueError(f"Invalid header name: {name}")
    return name


def checked_header_value(value: str) -> str:
    if "\r" in value or "\n" in value:
        raise ValueError(f"Invalid header value contains newline: {value}")
    if len(value) > 8192:
        raise ValueError(f"Header value too long: {len(value)} bytes")
    sanitized = "".join(char for char in value if ord(char) >= 32 or char == "\t")
    if _PATTERNS["_HEADER_VALUE_FORBIDDEN_RE"].search(sanitized):
        raise ValueError(
            "Invalid header value contains a character a response cannot carry"
        )
    return sanitized


def _check_named_header_settings(raw: Mapping[str, object]) -> None:
    for key in SECURITY_HEADER_NAMES:
        value = raw.get(key)
        if value is None or (key == "permissions_policy" and not value):
            continue
        if not isinstance(value, str):
            raise ValueError(f"the {key} setting must be a string")
        checked_header_value(value)


def _check_mapping_settings(raw: Mapping[str, object]) -> None:
    csp = raw.get("csp")
    if csp:
        if not isinstance(csp, Mapping):
            raise ValueError("the csp setting must map each directive to its sources")
        for directive, sources in csp.items():
            require_clean_csp_directive(directive, sources)
    hsts = raw.get("hsts")
    if hsts:
        if not isinstance(hsts, Mapping):
            raise ValueError("the hsts setting must be a mapping of its options")
        if hsts.get("max_age") is not None:
            require_valid_hsts_max_age(hsts["max_age"])


def _check_custom_headers(custom: object) -> None:
    if not custom:
        return
    if not isinstance(custom, Mapping):
        raise ValueError("the custom setting must map header names to values")
    for name, value in custom.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise ValueError(
                f"Custom header names and values must be strings: {name!r}"
            )
        checked_header_name(name)
        checked_header_value(value)


def checked_security_headers_config(raw: Mapping[str, object]) -> None:
    if security_headers_are_off(raw):
        return
    _check_named_header_settings(raw)
    _check_mapping_settings(raw)
    _check_custom_headers(raw.get("custom"))


def is_valid_cors_origin(value: str) -> bool:
    return _PATTERNS["_ORIGIN_TOKEN_RE"].fullmatch(value) is not None


CORS_VALUE_CHECKS: dict[str, Callable[[str], bool]] = {
    "cors_origins": is_valid_cors_origin,
    "cors_allow_methods": is_http_token,
    "cors_allow_headers": is_http_token,
    "cors_expose_headers": is_http_token,
}


def _refused_cors_fields(keys: Mapping[str, object]) -> list[str]:
    refused: list[str] = []
    for name, accepts in CORS_VALUE_CHECKS.items():
        value = keys.get(name)
        if isinstance(value, list) and not all(
            isinstance(item, str) and accepts(item) for item in value
        ):
            refused.append(name)
    return refused


@dataclass(frozen=True)
class CorsParams:
    enabled: bool
    origins: tuple[str, ...]
    credentials: bool
    methods: tuple[str, ...]
    headers: tuple[str, ...]
    max_age: int
    expose: tuple[str, ...]


class CorsFieldsConfig(Protocol):
    @property
    def enable_cors(self) -> bool: ...

    @property
    def cors_allow_origins(self) -> list[str]: ...

    @property
    def cors_allow_credentials(self) -> bool: ...

    @property
    def cors_allow_methods(self) -> list[str]: ...

    @property
    def cors_allow_headers(self) -> list[str]: ...

    @property
    def cors_max_age(self) -> int: ...

    @property
    def cors_expose_headers(self) -> list[str]: ...


def cors_params_of(config: CorsFieldsConfig) -> CorsParams:
    return CorsParams(
        enabled=bool(config.enable_cors),
        origins=tuple(config.cors_allow_origins or ()),
        credentials=bool(config.cors_allow_credentials),
        methods=tuple(config.cors_allow_methods or ()),
        headers=tuple(config.cors_allow_headers or ()),
        max_age=int(config.cors_max_age),
        expose=tuple(config.cors_expose_headers or ()),
    )


def _bool_key(keys: Mapping[str, object], name: str, default: bool) -> bool:
    return bool(keys.get(name, default))


def _strings_key(
    keys: Mapping[str, object], name: str, default: tuple[str, ...]
) -> tuple[str, ...]:
    value = keys.get(name, default)
    return tuple(map(str, value)) if isinstance(value, (list, tuple)) else default


def _seconds_key(keys: Mapping[str, object], name: str, default: int) -> int:
    value = keys.get(name, default)
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def merge_cors(
    base: CorsParams, keys: Mapping[str, object]
) -> tuple[CorsParams, str | None]:
    """The app's CORS with the override's passed keys applied, and why it was refused.

    A merge that would be a wildcard origin with credentials is refused: the app
    keeps its own CORS and the reason is returned.
    """
    if not CORS_OVERRIDE_KEYS & keys.keys():
        return base, None
    refused = _refused_cors_fields(keys)
    keys = {name: value for name, value in keys.items() if name not in refused}
    merged = CorsParams(
        enabled=_bool_key(keys, "enable_cors", base.enabled),
        origins=_strings_key(keys, "cors_origins", base.origins),
        credentials=_bool_key(keys, "cors_allow_credentials", base.credentials),
        methods=_strings_key(keys, "cors_allow_methods", base.methods),
        headers=_strings_key(keys, "cors_allow_headers", base.headers),
        max_age=_seconds_key(keys, "cors_max_age", base.max_age),
        expose=_strings_key(keys, "cors_expose_headers", base.expose),
    )
    if merged.enabled and "*" in merged.origins and merged.credentials:
        return base, "a wildcard origin cannot be combined with credentials"
    if refused:
        return merged, (
            f"{', '.join(refused)} hold a control character or an invalid origin, "
            "each of those fields keeps the app's own value"
        )
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
