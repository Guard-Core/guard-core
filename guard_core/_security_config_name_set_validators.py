from typing import Any

from guard_core.handlers.suspatterns_handler import ALL_DETECTION_CATEGORIES


def _frozenset_of_names(v: Any, field_name: str) -> frozenset[Any]:
    try:
        return frozenset(v)
    except TypeError:
        raise ValueError(
            f"{field_name} must be a collection of hashable names, "
            f"got {type(v).__name__}"
        ) from None


def _validate_enabled_detection_categories_value(v: Any) -> frozenset[str]:
    result = _frozenset_of_names(v, "enabled_detection_categories")
    unknown = result - ALL_DETECTION_CATEGORIES
    if unknown:
        raise ValueError(
            f"Unknown detection categories: {sorted(unknown, key=str)}. "
            f"Valid: {sorted(ALL_DETECTION_CATEGORIES)}"
        )
    return result


def _validate_muted_event_types_value(v: Any) -> frozenset[str]:
    from guard_core.core.events.event_types import EVENT_TYPE_VALUES

    result = _frozenset_of_names(v, "muted_event_types")
    invalid = result - EVENT_TYPE_VALUES
    if invalid:
        raise ValueError(
            f"Unknown event types in muted_event_types: "
            f"{sorted(invalid, key=str)}. "
            f"Valid: {sorted(EVENT_TYPE_VALUES)}"
        )
    return result


def _validate_muted_metric_types_value(v: Any) -> frozenset[str]:
    from guard_core.core.events.event_types import METRIC_TYPE_VALUES

    result = _frozenset_of_names(v, "muted_metric_types")
    invalid = result - METRIC_TYPE_VALUES
    if invalid:
        raise ValueError(
            f"Unknown metric types in muted_metric_types: "
            f"{sorted(invalid, key=str)}. "
            f"Valid: {sorted(METRIC_TYPE_VALUES)}"
        )
    return result


def _validate_muted_check_logs_value(v: Any) -> frozenset[str]:
    from guard_core.core.events.event_types import CHECK_NAME_VALUES

    result = _frozenset_of_names(v, "muted_check_logs")
    invalid = result - CHECK_NAME_VALUES
    if invalid:
        raise ValueError(
            f"Unknown check names in muted_check_logs: "
            f"{sorted(invalid, key=str)}. "
            f"Valid: {sorted(CHECK_NAME_VALUES)}"
        )
    return result


def _validate_sensitive_name_set_value(v: Any, field_name: str) -> frozenset[str]:
    if isinstance(v, str | bytes):
        raise ValueError(
            f"{field_name} must be a collection of names, not a bare string"
        )
    result = _frozenset_of_names(v, field_name)
    if not all(isinstance(item, str) for item in result):
        raise ValueError(f"{field_name} items must be strings")
    return result
