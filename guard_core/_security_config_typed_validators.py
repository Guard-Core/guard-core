from typing import Any

from pydantic import TypeAdapter, ValidationError


def _validate_typed_collection_field_value(
    v: Any, *, adapter: TypeAdapter[Any], field_name: str
) -> Any:
    try:
        return adapter.validate_python(v)
    except ValidationError as exc:
        raise ValueError(f"{field_name} is invalid: {exc}") from exc


_STR_LIST_ADAPTER: TypeAdapter[list[str]] = TypeAdapter(list[str])
_OPTIONAL_STR_LIST_ADAPTER: TypeAdapter[list[str] | None] = TypeAdapter(
    list[str] | None
)
_STR_SET_ADAPTER: TypeAdapter[set[str]] = TypeAdapter(set[str])
_STR_SET_OR_CATEGORY_MAP_ADAPTER: TypeAdapter[set[str] | dict[str, set[str]]] = (
    TypeAdapter(set[str] | dict[str, set[str]])
)
_INT_KEYED_STR_DICT_ADAPTER: TypeAdapter[dict[int, str]] = TypeAdapter(dict[int, str])
_STR_KEYED_STR_DICT_ADAPTER: TypeAdapter[dict[str, str]] = TypeAdapter(dict[str, str])
_OPTIONAL_STR_ANY_DICT_ADAPTER: TypeAdapter[dict[str, Any] | None] = TypeAdapter(
    dict[str, Any] | None
)
