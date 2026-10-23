from typing import Any


def _validate_bool_field_value(v: Any, *, field_name: str) -> bool:
    if not isinstance(v, bool):
        raise ValueError(f"{field_name} must be a bool, got {type(v).__name__}")
    return v


def _validate_optional_callable_field_value(v: Any, *, field_name: str) -> Any:
    if v is not None and not callable(v):
        raise ValueError(
            f"{field_name} must be callable or None, got {type(v).__name__}"
        )
    return v


def _validate_int_field_value(v: Any, *, field_name: str) -> int:
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError(f"{field_name} must be an int, got {type(v).__name__}")
    return v


def _validate_positive_int_field_value(v: Any, *, field_name: str) -> int:
    value = _validate_int_field_value(v, field_name=field_name)
    if value < 1:
        raise ValueError(f"{field_name} must be >= 1, got {value}")
    return value


def _validate_str_list_field_value(v: Any, *, field_name: str) -> list[str]:
    if not isinstance(v, list) or not all(isinstance(item, str) for item in v):
        raise ValueError(f"{field_name} must be a list of str")
    return v


def _validate_endpoint_rate_limits_value(v: Any) -> dict[str, tuple[int, int]]:
    if not isinstance(v, dict):
        raise ValueError(f"endpoint_rate_limits must be a dict, got {type(v).__name__}")
    for key, entry in v.items():
        if not isinstance(key, str):
            raise ValueError(
                f"endpoint_rate_limits keys must be str, got {type(key).__name__}"
            )
        if (
            not isinstance(entry, tuple)
            or len(entry) != 2
            or not all(isinstance(n, int) and not isinstance(n, bool) for n in entry)
        ):
            raise ValueError(
                f"endpoint_rate_limits[{key!r}] must be a (int, int) tuple, "
                f"got {entry!r}"
            )
    return v
