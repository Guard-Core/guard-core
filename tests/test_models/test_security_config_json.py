import json
from collections.abc import Callable
from types import MappingProxyType
from typing import Literal

import pytest

from guard_core.handlers.ipinfo_handler import IPInfoManager
from guard_core.models import SecurityConfig, ThreatBanConfig

_HANDLER_FIELDS = (
    "on_error",
    "on_block",
    "custom_request_check",
    "auth_verifier",
    "custom_response_modifier",
    "cloud_ip_store",
    "geo_ip_handler",
)


class _Store:
    async def get(self, provider: str) -> set[str] | None:
        return None

    async def set(
        self, provider: str, ranges: set[str], ttl: int | None = None
    ) -> None:
        return None

    async def clear(self) -> None:
        return None


def _hook(*args: object) -> None:
    return None


def _factory(redis_handler: object) -> _Store:
    return _Store()


def _every_field_set(
    cloud_ip_store: object | Callable[..., object],
) -> SecurityConfig:
    base = SecurityConfig()
    fields = {name: getattr(base, name) for name in SecurityConfig.model_fields}
    fields.update(
        threat_ban_config={"xss": ThreatBanConfig(threshold=2, duration=60)},
        on_error=_hook,
        on_block=_hook,
        custom_request_check=_hook,
        auth_verifier=_hook,
        custom_response_modifier=_hook,
        cloud_ip_store=cloud_ip_store,
        geo_ip_handler=IPInfoManager(token="not-a-real-token"),
    )
    config = SecurityConfig(**fields)
    assert set(config.model_fields_set) == set(SecurityConfig.model_fields)
    return config


def test_default_config_dumps_to_json() -> None:
    dumped = json.loads(SecurityConfig().model_dump_json())
    assert dumped["threat_ban_config"] == {}
    assert set(dumped) == set(SecurityConfig.model_fields)


def test_default_config_json_round_trips_through_model_dump_mode_json() -> None:
    config = SecurityConfig()
    assert json.loads(config.model_dump_json()) == config.model_dump(mode="json")


def test_threat_ban_config_entries_serialize_as_mappings() -> None:
    config = SecurityConfig(
        threat_ban_config={"xss": ThreatBanConfig(threshold=2, duration=60)}
    )
    dumped = json.loads(config.model_dump_json())
    assert dumped["threat_ban_config"] == {"xss": {"threshold": 2, "duration": 60}}


@pytest.mark.parametrize("store", [_Store(), _factory])
def test_every_field_set_dumps_to_json_with_handler_names(store: object) -> None:
    dumped = json.loads(_every_field_set(store).model_dump_json())
    assert dumped["on_error"] == f"{_hook.__module__}._hook"
    assert dumped["custom_request_check"] == f"{_hook.__module__}._hook"
    assert (
        dumped["geo_ip_handler"] == "guard_core.handlers.ipinfo_handler.IPInfoManager"
    )
    expected_store = (
        f"{_factory.__module__}._factory"
        if store is _factory
        else f"{_Store.__module__}._Store"
    )
    assert dumped["cloud_ip_store"] == expected_store
    assert "not-a-real-token" not in json.dumps(dumped)


def test_unset_handler_fields_dump_as_null() -> None:
    dumped = json.loads(SecurityConfig().model_dump_json())
    assert all(dumped[name] is None for name in _HANDLER_FIELDS)


def test_model_dump_keeps_python_objects() -> None:
    config = _every_field_set(_Store())
    dumped = config.model_dump()
    assert isinstance(dumped["threat_ban_config"], MappingProxyType)
    assert dumped["on_error"] is _hook
    assert isinstance(dumped["cloud_ip_store"], _Store)
    assert isinstance(dumped["geo_ip_handler"], IPInfoManager)


_MODES: tuple[Literal["validation", "serialization"], ...] = (
    "validation",
    "serialization",
)


@pytest.mark.parametrize("mode", _MODES)
def test_json_schema_describes_every_field(
    mode: Literal["validation", "serialization"],
) -> None:
    schema = SecurityConfig.model_json_schema(mode=mode)
    assert set(schema["properties"]) == set(SecurityConfig.model_fields)
    ban = schema["properties"]["threat_ban_config"]
    assert ban["type"] == "object"
    assert set(ban["additionalProperties"]["properties"]) == {"threshold", "duration"}
    for name in _HANDLER_FIELDS:
        assert {"type": "null"} in schema["properties"][name]["anyOf"]
        assert {"type": "string"} in [
            {"type": branch.get("type")}
            for branch in schema["properties"][name]["anyOf"]
        ]
