import json
from collections.abc import Callable
from urllib.parse import urlencode

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.decorators.base import BaseSecurityDecorator, RouteConfig
from guard_core.sync.decorators.content_filtering import ContentFilteringMixin
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

SENSITIVE_FILE = ".env"
SCRIPT = "<script>alert(1)</script>"
MULTIPART_TYPE = "multipart/form-data; boundary=B0"


_BodyFields = set[str] | dict[str, set[str]]


class _FakeDecorator(BaseSecurityDecorator, ContentFilteringMixin):
    pass


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


def _route_config(body_fields: _BodyFields) -> RouteConfig:
    decorator = _FakeDecorator(SyncSecurityConfig())

    def target() -> None:
        pass

    decorated = decorator.detection_exclusion(body_fields=body_fields)(target)
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


def _json(payload: object) -> SyncMockGuardRequest:
    return _request("application/json", json.dumps(payload).encode())


def _form(**fields: str) -> SyncMockGuardRequest:
    return _request("application/x-www-form-urlencoded", urlencode(fields).encode())


def _multipart(name: str, value: str) -> SyncMockGuardRequest:
    body = (
        f'--B0\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'
        f"{value}\r\n--B0--\r\n"
    ).encode()
    return _request(MULTIPART_TYPE, body)


def _is_threat(request: SyncMockGuardRequest, body_fields: _BodyFields) -> bool:
    config = SyncSecurityConfig(enable_redis=False, rate_limit=10_000_000)
    route_config = _route_config(body_fields)
    return (detect_penetration_attempt(request, config, route_config)).is_threat


def test_the_set_form_is_stored_as_a_set() -> None:
    assert _route_config({"note", "memo"}).excluded_detection_body_fields == {
        "note",
        "memo",
    }


def test_the_map_form_is_stored_as_a_map() -> None:
    stored = _route_config({"note": {"sensitive_file"}}).excluded_detection_body_fields
    assert stored == {"note": {"sensitive_file"}}


@pytest.mark.parametrize(
    "bad",
    [{"note": set()}, {"note": {"not_a_category"}}, {1: {"xss"}}, {"note": "xss"}],
)
def test_the_map_form_is_validated_like_params(bad: dict[object, object]) -> None:
    errors: list[str] = []
    for keyword in ("params", "body_fields"):
        decorator = _FakeDecorator(SyncSecurityConfig())
        exclude: Callable[..., Callable[[Callable[[], None]], Callable[[], None]]] = (
            decorator.detection_exclusion
        )

        def target() -> None:
            pass

        with pytest.raises(ValueError) as caught:
            exclude(**{keyword: bad})(target)
        errors.append(str(caught.value))
    assert errors[0].replace("excluded_detection_params", "<option>") == errors[
        1
    ].replace("excluded_detection_body_fields", "<option>")


@pytest.mark.parametrize("surface", ["json", "form", "multipart"])
def test_a_category_listed_for_a_field_skips_only_that_category(
    surface: str,
) -> None:
    def build(value: str, field: str = "note") -> SyncMockGuardRequest:
        if surface == "json":
            return _json({field: value})
        if surface == "form":
            return _form(**{field: value})
        return _multipart(field, value)

    exclusion = {"note": {"sensitive_file"}}
    assert _is_threat(build(SENSITIVE_FILE), exclusion) is False
    assert _is_threat(build(SCRIPT), exclusion) is True
    assert _is_threat(build(SENSITIVE_FILE, field="other"), exclusion) is True
    assert _is_threat(build(SENSITIVE_FILE), {"note"}) is False
    assert _is_threat(build(SCRIPT), {"note"}) is False
    assert _is_threat(build(SENSITIVE_FILE), {"other"}) is True


def test_a_category_listed_for_a_field_covers_its_nested_values() -> None:
    exclusion = {"note": {"sensitive_file"}}
    nested = {"note": {"inner": [SENSITIVE_FILE, {"deep": SENSITIVE_FILE}]}}
    assert _is_threat(_json(nested), exclusion) is False
    attack = {"note": {"inner": [SENSITIVE_FILE, {"deep": SCRIPT}]}}
    assert _is_threat(_json(attack), exclusion) is True
    sibling = {"note": {"inner": SENSITIVE_FILE}, "other": SENSITIVE_FILE}
    assert _is_threat(_json(sibling), exclusion) is True


def test_a_field_name_is_scanned_in_the_categories_left_for_the_field() -> None:
    exclusion = {"note": {"sensitive_file"}}
    assert _is_threat(_json({"note": "fine"}), exclusion) is False
    assert _is_threat(_json({"note": SENSITIVE_FILE, "x": "<b>"}), exclusion) is False


def test_a_field_name_listed_in_another_case_still_applies() -> None:
    assert (
        _is_threat(_json({"Note": SENSITIVE_FILE}), {"NOTE": {"sensitive_file"}})
        is False
    )


def test_a_category_listed_for_a_field_of_an_embedded_json_value() -> None:
    exclusion = {"note": {"sensitive_file"}}
    request = SyncMockGuardRequest(
        path="/api", query_params={"q": json.dumps({"note": SENSITIVE_FILE})}
    )
    assert _is_threat(request, exclusion) is False
    request = SyncMockGuardRequest(
        path="/api", query_params={"q": json.dumps({"other": SENSITIVE_FILE})}
    )
    assert _is_threat(request, exclusion) is True
