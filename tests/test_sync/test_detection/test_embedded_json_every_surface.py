import json
from collections.abc import Callable
from urllib.parse import urlencode

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

XSS_ESCAPED = "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"
SQLI_ESCAPED = "1\\u0027 OR \\u00271\\u0027=\\u00271"
BENIGN = "hello world"
ATTACKS = {"xss": XSS_ESCAPED, "sqli": SQLI_ESCAPED}
LEVELS = [1, 2, 3]
DEPTHS = [1, 10, 500, 980, 1000, 1500, 3000]
DEEP_DEPTHS = [1000, 1500, 3000]


def _nested(levels: int, payload: str) -> str:
    text = '{"q":"' + payload + '"}'
    for _ in range(levels - 1):
        text = json.dumps({"x": text})
    return text


def _raw_body(content_type: str) -> Callable[[str], SyncMockGuardRequest]:
    def build(value: str) -> SyncMockGuardRequest:
        body = json.dumps({"data": value}).encode()
        return SyncMockGuardRequest(
            path="/api",
            method="POST",
            headers={"content-type": content_type, "content-length": str(len(body))},
            body_content=body,
        )

    return build


def _form(value: str) -> SyncMockGuardRequest:
    body = urlencode({"data": value}).encode()
    return SyncMockGuardRequest(
        path="/api",
        method="POST",
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "content-length": str(len(body)),
        },
        body_content=body,
    )


def _query(value: str) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(path="/api", query_params={"data": value})


SURFACES: dict[str, Callable[[str], SyncMockGuardRequest]] = {
    "query": _query,
    "form": _form,
    "json": _raw_body("application/json"),
    "text_plain": _raw_body("text/plain"),
    "octet_stream": _raw_body("application/octet-stream"),
}


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


def _is_threat(request: SyncMockGuardRequest) -> bool:
    config = SecurityConfig(enable_redis=False, rate_limit=10_000_000)
    result = detect_penetration_attempt(request, config)
    return result.is_threat


@pytest.mark.parametrize("level", LEVELS)
@pytest.mark.parametrize("attack", sorted(ATTACKS))
@pytest.mark.parametrize("surface", sorted(SURFACES))
def test_an_escaped_payload_nested_in_stringified_json_is_found_on_every_surface(
    surface: str, attack: str, level: int
) -> None:
    value = _nested(level, ATTACKS[attack])
    assert _is_threat(SURFACES[surface](value)) is True


@pytest.mark.parametrize("level", LEVELS)
@pytest.mark.parametrize("surface", sorted(SURFACES))
def test_benign_stringified_json_stays_clean_on_every_surface(
    surface: str, level: int
) -> None:
    assert _is_threat(SURFACES[surface](_nested(level, BENIGN))) is False


_INNER = '{"q":"' + XSS_ESCAPED + '"}'
_INNER_SQLI = '{"q":"' + SQLI_ESCAPED + '"}'


def _wrapped_once(inner: str, depth: int) -> str:
    return "[" * depth + json.dumps(inner) + "]" * depth


def _escaped_twice(inner: str, depth: int) -> str:
    return "[" * depth + json.dumps(json.dumps({"k": inner})) + "]" * depth


@pytest.mark.parametrize("depth", DEPTHS)
@pytest.mark.parametrize("inner", [_INNER, _INNER_SQLI], ids=["xss", "sqli"])
def test_an_escaped_payload_is_found_at_every_nesting_depth(
    inner: str, depth: int
) -> None:
    assert _is_threat(_query(_wrapped_once(inner, depth))) is True


@pytest.mark.parametrize("depth", DEEP_DEPTHS)
@pytest.mark.parametrize("surface", ["query", "json", "text_plain"])
@pytest.mark.parametrize("inner", [_INNER, _INNER_SQLI], ids=["xss", "sqli"])
def test_a_payload_escaped_twice_is_found_past_the_parser_limit(
    inner: str, surface: str, depth: int
) -> None:
    value = _escaped_twice(inner, depth)
    assert _is_threat(SURFACES[surface](value)) is True


@pytest.mark.parametrize("depth", DEPTHS)
@pytest.mark.parametrize("surface", ["query", "json", "text_plain"])
def test_a_benign_value_nested_to_any_depth_is_not_refused(
    surface: str, depth: int
) -> None:
    plain = "[" * depth + json.dumps(BENIGN) + "]" * depth
    escaped = _escaped_twice('{"q":"' + BENIGN + '"}', depth)
    assert _is_threat(SURFACES[surface](plain)) is False
    assert _is_threat(SURFACES[surface](escaped)) is False
