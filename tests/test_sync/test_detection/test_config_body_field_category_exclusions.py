import json
from collections.abc import Callable
from typing import Any, cast
from urllib.parse import urlencode

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.decorators.base import BaseSecurityDecorator, RouteConfig
from guard_core.sync.decorators.content_filtering import ContentFilteringMixin
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

SENSITIVE_FILE = ".env"
SCRIPT = "<script>alert(1)</script>"
MULTIPART_TYPE = "multipart/form-data; boundary=B0"


class _FakeDecorator(BaseSecurityDecorator, ContentFilteringMixin):
    pass


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


def _route_config(body_fields: Any) -> RouteConfig:
    decorator = _FakeDecorator(SecurityConfig())

    def target() -> None:
        pass

    decorated = cast(
        Callable[..., Any],
        decorator.detection_exclusion(body_fields=body_fields)(target),
    )
    route_config = decorator.get_route_config(decorator._get_route_id(decorated))
    assert route_config is not None
    return route_config


def _request(content_type: str, body: bytes) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(
        path="/api",
        method="POST",
        headers={"content-type": content_type, "content-length": str(len(body))},
        body_content=body,
    )


def _body(surface: str, fields: dict[str, str]) -> SyncMockGuardRequest:
    if surface == "json":
        return _request("application/json", json.dumps(fields).encode())
    if surface == "form":
        return _request("application/x-www-form-urlencoded", urlencode(fields).encode())
    parts = "".join(
        f'--B0\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'
        for name, value in fields.items()
    )
    return _request(MULTIPART_TYPE, f"{parts}--B0--\r\n".encode())


def _is_threat(
    request: SyncMockGuardRequest,
    global_fields: Any,
    route_fields: Any = None,
    **config_options: Any,
) -> bool:
    config = SecurityConfig(
        enable_redis=False,
        rate_limit=10_000_000,
        excluded_detection_body_fields=global_fields,
        **config_options,
    )
    route_config = None if route_fields is None else _route_config(route_fields)
    return (detect_penetration_attempt(request, config, route_config)).is_threat


def test_the_set_form_is_stored_as_a_set() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"note", "memo"})
    assert config.excluded_detection_body_fields == {"note", "memo"}


def test_the_map_form_is_stored_as_a_map() -> None:
    config = SecurityConfig(excluded_detection_body_fields={"note": {"sensitive_file"}})
    assert config.excluded_detection_body_fields == {"note": {"sensitive_file"}}


def test_a_reassigned_map_is_validated() -> None:
    config = SecurityConfig()
    config.excluded_detection_body_fields = {"note": {"xss"}}
    assert config.excluded_detection_body_fields == {"note": {"xss"}}
    with pytest.raises(ValueError, match="Unknown detection categories"):
        config.excluded_detection_body_fields = {"note": {"not_a_category"}}


@pytest.mark.parametrize(
    "bad",
    [{"note": set()}, {"note": {"not_a_category"}}, {1: {"xss"}}, {"note": "xss"}],
)
def test_the_map_form_is_validated_like_the_decorator(bad: Any) -> None:
    decorator = _FakeDecorator(SecurityConfig())

    def target() -> None:
        pass

    with pytest.raises(ValueError) as from_decorator:
        decorator.detection_exclusion(body_fields=bad)(target)
    with pytest.raises(ValueError) as from_config:
        SecurityConfig(excluded_detection_body_fields=bad)
    decorator_text = str(from_decorator.value)
    renamed_text = decorator_text.replace(
        "excluded_detection_params is invalid",
        "excluded_detection_body_fields is invalid",
    )
    assert renamed_text in str(from_config.value)


@pytest.mark.parametrize("surface", ["json", "form", "multipart"])
def test_a_category_listed_for_a_field_skips_only_that_category(
    surface: str,
) -> None:
    exclusion = {"note": {"sensitive_file"}}
    assert _is_threat(_body(surface, {"note": SENSITIVE_FILE}), exclusion) is False
    assert _is_threat(_body(surface, {"note": SCRIPT}), exclusion) is True
    assert _is_threat(_body(surface, {"other": SENSITIVE_FILE}), exclusion) is True
    assert _is_threat(_body(surface, {"note": SENSITIVE_FILE}), {"note"}) is False
    assert _is_threat(_body(surface, {"note": SCRIPT}), {"note"}) is False
    assert _is_threat(_body(surface, {"note": SENSITIVE_FILE}), {"other"}) is True


def test_a_category_listed_for_a_field_covers_its_nested_values() -> None:
    exclusion = {"note": {"sensitive_file"}}
    nested = {"note": {"inner": [SENSITIVE_FILE, {"deep": SENSITIVE_FILE}]}}
    request = _request("application/json", json.dumps(nested).encode())
    assert _is_threat(request, exclusion) is False
    attack = {"note": {"inner": [SENSITIVE_FILE, {"deep": SCRIPT}]}}
    request = _request("application/json", json.dumps(attack).encode())
    assert _is_threat(request, exclusion) is True


def test_a_route_map_replaces_the_global_map() -> None:
    global_map = {"note": {"xss"}}
    route_map = {"other": {"xss"}}
    note = _body("json", {"note": SCRIPT})
    other = _body("json", {"other": SCRIPT})
    assert _is_threat(note, global_map) is False
    assert _is_threat(note, global_map, route_map) is True
    assert _is_threat(other, global_map, route_map) is False


def test_a_route_set_replaces_the_global_map() -> None:
    global_map = {"note": {"xss"}}
    assert _is_threat(_body("json", {"note": SCRIPT}), global_map, {"other"}) is True
    assert _is_threat(_body("json", {"other": SCRIPT}), global_map, {"other"}) is False


_JUNK = {f"k{i}": "v" for i in range(300)}


@pytest.mark.parametrize("surface", ["json", "form", "multipart"])
def test_the_remainder_honours_the_category_map_of_a_field(surface: str) -> None:
    exclusion = {"note": {"sensitive_file"}}
    options = {"detection_max_scan_values": 20}

    def threat(value: str, field: str = "note") -> bool:
        request = _body(surface, {**_JUNK, field: value})
        return _is_threat(request, set(), exclusion, **options)

    assert threat(SENSITIVE_FILE) is False
    assert threat(SCRIPT) is True
    assert threat(SENSITIVE_FILE, field="other") is True


def test_the_remainder_honours_the_map_of_a_nested_field() -> None:
    exclusion = {"note": {"sensitive_file"}}
    options = {"detection_max_scan_values": 20}
    clean = _request(
        "application/json",
        json.dumps({**_JUNK, "z": {"note": SENSITIVE_FILE}}).encode(),
    )
    attack = _request(
        "application/json", json.dumps({**_JUNK, "z": {"note": SCRIPT}}).encode()
    )
    assert _is_threat(clean, set(), exclusion, **options) is False
    assert _is_threat(attack, set(), exclusion, **options) is True


def test_a_bare_string_is_rejected_naming_the_field() -> None:
    with pytest.raises(ValueError, match="excluded_detection_body_fields"):
        SecurityConfig(excluded_detection_body_fields="nope")
    config: Any = SecurityConfig()
    with pytest.raises(ValueError, match="excluded_detection_body_fields"):
        config.excluded_detection_body_fields = "nope"
