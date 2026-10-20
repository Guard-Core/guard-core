from typing import Annotated, Any

from pydantic import AfterValidator, BeforeValidator

from guard_core._config_field_revalidators import _validate_str_list_field_value
from guard_core.handlers._dynamic_rule_persistence import parse_purge_target


def _validate_purge_target(value: str | None) -> str | None:
    if value is not None:
        parse_purge_target(value)
    return value


PurgeTarget = Annotated[str | None, AfterValidator(_validate_purge_target)]


def _validate_emergency_exempt_paths_value(v: Any) -> list[str]:
    from guard_core.core.validation.path_matching import normalize_url_path

    entries = _validate_str_list_field_value(v, field_name="emergency_exempt_paths")
    for entry in entries:
        normalized = normalize_url_path(entry)
        if normalized is None:
            raise ValueError(
                f"emergency_exempt_paths entry {entry!r} could not be normalized "
                "(malformed percent-encoding or invalid UTF-8); it would exempt "
                "nothing at request time. Fix or remove it."
            )
        if normalized == "/":
            raise ValueError(
                f"emergency_exempt_paths entry {entry!r} is the root path '/', "
                "which would leave the whole application open during an "
                "emergency lockdown. List the probe paths only."
            )
    return entries


EmergencyExemptPaths = Annotated[
    list[str], BeforeValidator(_validate_emergency_exempt_paths_value)
]
