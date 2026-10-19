import json
from urllib.parse import quote

import pytest

from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

ATTACK = "1' UNION SELECT password FROM users--"
_BOUNDARY = "guardboundary"


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


def _post(body: bytes, content_type: str, path: str = "/api") -> MockGuardRequest:
    return MockGuardRequest(
        path=path,
        method="POST",
        body_content=body,
        headers={"content-type": content_type, "content-length": str(len(body))},
    )


async def _is_threat(
    request: MockGuardRequest, config: SecurityConfig | None = None
) -> bool:
    result = await detect_penetration_attempt(request, config or SecurityConfig())
    return result.is_threat


def _json_text(*pairs: tuple[str, str]) -> bytes:
    return (
        "{" + ", ".join(f"{json.dumps(k)}: {json.dumps(v)}" for k, v in pairs) + "}"
    ).encode()


def _multipart(*fields: tuple[str, str]) -> bytes:
    parts = "".join(
        f"--{_BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'
        for name, value in fields
    )
    return f"{parts}--{_BOUNDARY}--\r\n".encode()


async def test_json_attack_in_the_first_of_two_repeated_keys_is_flagged() -> None:
    body = _json_text(("q", ATTACK), ("q", "hello"))
    assert await _is_threat(_post(body, "application/json")) is True


async def test_json_attack_in_the_last_of_two_repeated_keys_is_flagged() -> None:
    body = _json_text(("q", "hello"), ("q", ATTACK))
    assert await _is_threat(_post(body, "application/json")) is True


async def test_json_attack_in_the_middle_of_three_repeated_keys_is_flagged() -> None:
    body = _json_text(("q", "a"), ("q", ATTACK), ("q", "b"))
    assert await _is_threat(_post(body, "application/json")) is True


async def test_json_repeated_key_inside_a_nested_object_is_flagged() -> None:
    inner = _json_text(("q", ATTACK), ("q", "hello")).decode()
    body = f'{{"outer": {{"deep": [{inner}]}}}}'.encode()
    assert await _is_threat(_post(body, "application/json")) is True


async def test_json_repeated_key_below_the_depth_cap_is_flagged() -> None:
    inner = _json_text(("q", ATTACK), ("q", "hello")).decode()
    body = f'{{"outer": {inner}}}'.encode()
    config = SecurityConfig(detection_max_json_depth=2)
    assert await _is_threat(_post(body, "application/json"), config) is True


async def test_json_repeated_key_with_benign_values_is_clean() -> None:
    body = _json_text(("q", "hello"), ("q", "world"))
    assert await _is_threat(_post(body, "application/json")) is False


async def test_json_repeated_key_after_a_sensitive_name_is_redacted_in_the_report() -> (
    None
):
    body = _json_text(("password", ATTACK), ("password", "hello"))
    result = await detect_penetration_attempt(
        _post(body, "application/json"), SecurityConfig()
    )
    assert result.is_threat is True
    assert ATTACK not in result.trigger_info


async def test_form_attack_in_the_first_of_two_repeated_names_is_flagged() -> None:
    body = f"q={quote(ATTACK)}&q=hello".encode()
    assert await _is_threat(_post(body, "application/x-www-form-urlencoded")) is True


async def test_form_attack_in_the_last_of_two_repeated_names_is_flagged() -> None:
    body = f"q=hello&q={quote(ATTACK)}".encode()
    assert await _is_threat(_post(body, "application/x-www-form-urlencoded")) is True


async def test_multipart_attack_in_the_first_of_two_repeated_names_is_flagged() -> None:
    body = _multipart(("q", ATTACK), ("q", "hello"))
    content_type = f"multipart/form-data; boundary={_BOUNDARY}"
    assert await _is_threat(_post(body, content_type)) is True


async def test_multipart_attack_in_the_last_of_two_repeated_names_is_flagged() -> None:
    body = _multipart(("q", "hello"), ("q", ATTACK))
    content_type = f"multipart/form-data; boundary={_BOUNDARY}"
    assert await _is_threat(_post(body, content_type)) is True


async def test_query_attack_in_the_first_of_two_repeated_keys_is_flagged() -> None:
    request = MockGuardRequest(path=f"/api?q={quote(ATTACK)}&q=hello")
    assert await _is_threat(request) is True


async def test_query_attack_in_the_last_of_two_repeated_keys_is_flagged() -> None:
    request = MockGuardRequest(path=f"/api?q=hello&q={quote(ATTACK)}")
    assert await _is_threat(request) is True


def test_object_without_a_repeated_key_stays_a_plain_dict() -> None:
    from guard_core._utils.body_json_scan import _json_object_with_every_pair

    parsed = json.loads(
        '{"a": 1, "b": {"c": 2}}', object_pairs_hook=_json_object_with_every_pair
    )
    assert type(parsed) is dict
    assert type(parsed["b"]) is dict
    assert parsed == {"a": 1, "b": {"c": 2}}


def test_object_with_a_repeated_key_lists_every_pair_and_serializes_them() -> None:
    from guard_core._utils.body_json_scan import _json_object_with_every_pair

    parsed = json.loads(
        '{"q": 1, "r": 2, "q": 3, "q": 4}',
        object_pairs_hook=_json_object_with_every_pair,
    )
    assert [(str(key), value) for key, value in parsed.items()] == [
        ("q", 1),
        ("r", 2),
        ("q", 3),
        ("q", 4),
    ]
    assert json.dumps(parsed, separators=(",", ":")) == '{"q":1,"r":2,"q":3,"q":4}'


def test_a_repeated_key_equals_only_itself() -> None:
    from guard_core._utils.body_json_scan import _RepeatedKey

    first, second = _RepeatedKey("q"), _RepeatedKey("q")
    assert first == first
    assert not first == second
    assert not first == "q"
    assert len({first, second, "q"}) == 3
