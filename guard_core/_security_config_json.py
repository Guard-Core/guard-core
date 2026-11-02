from types import MappingProxyType
from typing import Annotated, TypeVar

from pydantic import GetJsonSchemaHandler, PlainSerializer, WithJsonSchema
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import CoreSchema

from guard_core._security_config_field_validators import ThreatBanConfig

_T = TypeVar("_T")


def _dotted_name(value: object) -> str | None:
    if value is None:
        return None
    target = value if hasattr(value, "__qualname__") else type(value)
    return f"{target.__module__}.{target.__qualname__}"


def _threat_ban_entries(
    value: MappingProxyType[str, ThreatBanConfig],
) -> dict[str, ThreatBanConfig]:
    return dict(value)


_OBJECT_NAME_SCHEMA = WithJsonSchema(
    {
        "anyOf": [
            {
                "type": "string",
                "description": (
                    "Python object, serialized as its dotted module and qualified name"
                ),
            },
            {"type": "null"},
        ]
    }
)


class _ThreatBanMappingSchema:
    # Built when a schema is asked for, so importing guard_core pays nothing.
    def __get_pydantic_json_schema__(
        self, schema: CoreSchema, handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        return {
            "type": "object",
            "additionalProperties": ThreatBanConfig.model_json_schema(),
        }


_DOTTED_NAME_WHEN_JSON = PlainSerializer(
    _dotted_name, return_type=str | None, when_used="json"
)

_ENTRIES_WHEN_JSON = PlainSerializer(
    _threat_ban_entries,
    return_type=dict[str, ThreatBanConfig],
    when_used="json",
)

NamedInJson = Annotated[_T, _DOTTED_NAME_WHEN_JSON, _OBJECT_NAME_SCHEMA]
MappingProxyInJson = Annotated[
    MappingProxyType[str, ThreatBanConfig],
    _ENTRIES_WHEN_JSON,
    _ThreatBanMappingSchema(),
]
