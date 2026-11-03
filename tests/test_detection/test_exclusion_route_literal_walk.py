import json
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from guard_core._utils import embedded_json_scan
from guard_core.decorators.base import RouteConfig
from guard_core.handlers.suspatterns_handler import (
    DetectionResult,
    SusPatternsManager,
    sus_patterns_handler,
)
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

XSS_ESCAPED = "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"
SQLI_ESCAPED = "1\\u0027 OR \\u00271\\u0027=\\u00271"
CONTENT_TYPES = ["text/plain", "application/octet-stream"]
_Exclusion = set[str] | dict[str, set[str]]
EXCLUSION_FORMS: list[_Exclusion] = [{"html"}, {"html": {"xss"}}]
MAX_SCANS_FOR_A_BODY_WITHOUT_A_BACKSLASH = 3


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


def _body(content_type: str, text: str) -> MockGuardRequest:
    payload = text.encode()
    return MockGuardRequest(
        path="/api",
        method="POST",
        headers={"content-type": content_type, "content-length": str(len(payload))},
        body_content=payload,
    )


def _inner(payload: str) -> str:
    # The payload sits one JSON string deeper, so only a walk that decodes the
    # literal sees it; a flat scan of the raw text decodes a single level.
    return json.dumps({"q": "@@"}).replace("@@", payload)


def _watch_detect(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    scanned: list[str] = []
    detect: Callable[..., Awaitable[DetectionResult]] = SusPatternsManager.detect

    async def counting_detect(
        self: SusPatternsManager, *args: object, **kwargs: object
    ) -> DetectionResult:
        if str(kwargs.get("context")).startswith("request_body"):
            scanned.append(str(kwargs.get("content", "")))
        return await detect(self, *args, **kwargs)

    monkeypatch.setattr(SusPatternsManager, "detect", counting_detect)
    return scanned


async def _is_threat(
    request: MockGuardRequest,
    route_fields: _Exclusion | None = None,
    config_fields: _Exclusion | None = None,
) -> bool:
    route_config = RouteConfig()
    if route_fields is not None:
        route_config.excluded_detection_body_fields = route_fields
    options: dict[str, Any] = {"enable_redis": False, "rate_limit": 10_000_000}
    if config_fields is not None:
        options["excluded_detection_body_fields"] = config_fields
    config = SecurityConfig(**options)
    return (await detect_penetration_attempt(request, config, route_config)).is_threat


def _route_or_config(form: _Exclusion, where: str) -> dict[str, _Exclusion]:
    return {"route_fields": form} if where == "route" else {"config_fields": form}


@pytest.mark.parametrize("where", ["route", "config"])
@pytest.mark.parametrize("form", EXCLUSION_FORMS)
@pytest.mark.parametrize("content_type", CONTENT_TYPES)
async def test_an_excluded_field_holding_an_escaped_xss_is_not_flagged(
    content_type: str, form: _Exclusion, where: str
) -> None:
    exclusion = _route_or_config(form, where)
    body = json.dumps({"html": _inner(XSS_ESCAPED), "name": "Mary"})
    assert await _is_threat(_body(content_type, body), **exclusion) is False


@pytest.mark.parametrize("where", ["route", "config"])
@pytest.mark.parametrize("form", EXCLUSION_FORMS)
@pytest.mark.parametrize("content_type", CONTENT_TYPES)
async def test_a_sibling_field_with_the_same_escaped_payload_is_flagged(
    content_type: str, form: _Exclusion, where: str
) -> None:
    exclusion = _route_or_config(form, where)
    inner = _inner(XSS_ESCAPED)
    body = json.dumps({"html": inner, "other": inner})
    assert await _is_threat(_body(content_type, body), **exclusion) is True


@pytest.mark.parametrize("where", ["route", "config"])
@pytest.mark.parametrize("content_type", CONTENT_TYPES)
async def test_a_map_form_exclusion_skips_only_its_categories_for_the_field(
    content_type: str, where: str
) -> None:
    exclusion = _route_or_config({"html": {"xss"}}, where)
    sqli = json.dumps({"html": _inner(SQLI_ESCAPED)})
    assert await _is_threat(_body(content_type, sqli), **exclusion) is True


@pytest.mark.parametrize("content_type", CONTENT_TYPES)
async def test_an_escaped_payload_in_an_unexcluded_field_is_flagged(
    content_type: str,
) -> None:
    body = json.dumps({"html": "fine", "q": _inner(XSS_ESCAPED)})
    assert await _is_threat(_body(content_type, body), {"html"}) is True


@pytest.mark.parametrize("content_type", CONTENT_TYPES)
async def test_a_repeated_key_cannot_hide_an_escaped_payload(
    content_type: str,
) -> None:
    body = f'{{"q": {json.dumps(_inner(XSS_ESCAPED))}, "q": "plain"}}'
    assert await _is_threat(_body(content_type, body), {"html"}) is True


@pytest.mark.parametrize("form", EXCLUSION_FORMS)
@pytest.mark.parametrize("content_type", CONTENT_TYPES)
async def test_a_body_that_is_not_json_keeps_the_flat_literal_scan(
    content_type: str, form: _Exclusion
) -> None:
    body = f'{{"html": "fine", "q": "{XSS_ESCAPED}"'
    assert await _is_threat(_body(content_type, body), form) is True


@pytest.mark.parametrize("content_type", CONTENT_TYPES)
async def test_a_body_that_nests_too_deep_to_parse_keeps_the_literal_scan(
    content_type: str,
) -> None:
    body = "[" * 600 + f'"{XSS_ESCAPED}"' + "]" * 600
    assert await _is_threat(_body(content_type, body), {"html"}) is True


@pytest.mark.parametrize("content_type", CONTENT_TYPES)
async def test_a_body_without_a_backslash_is_not_walked(
    content_type: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [{"id": index, "name": f"Mary {index}"} for index in range(60)]
    scanned = _watch_detect(monkeypatch)
    body = json.dumps({"rows": rows})
    assert await _is_threat(_body(content_type, body), {"html"}) is False
    assert len(scanned) <= MAX_SCANS_FOR_A_BODY_WITHOUT_A_BACKSLASH


@pytest.mark.parametrize("content_type", CONTENT_TYPES)
async def test_only_the_escaped_values_and_their_twins_are_walked(
    content_type: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [{"id": index, "name": f"Mary {index}"} for index in range(60)]
    payload = {"rows": rows, "a": "é", "b": "é", "note": "line\nbreak"}
    body = json.dumps(payload)
    scanned = _watch_detect(monkeypatch)
    assert await _is_threat(_body(content_type, body), {"html"}) is False
    assert scanned.count("é") == 2
    assert "line\nbreak" in scanned
    assert not any(text in ("Mary 7", "7") for text in scanned)


@pytest.mark.parametrize("content_type", CONTENT_TYPES)
async def test_an_escaped_payload_in_a_top_level_array_is_flagged(
    content_type: str,
) -> None:
    body = json.dumps(["fine", _inner(XSS_ESCAPED)])
    assert await _is_threat(_body(content_type, body), {"html"}) is True


@pytest.mark.parametrize("content_type", CONTENT_TYPES)
async def test_an_escaped_key_is_walked_even_when_its_value_is_not_text(
    content_type: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    scanned = _watch_detect(monkeypatch)
    body = '{"na\\u00efve": 1, "other": 2}'
    assert await _is_threat(_body(content_type, body), {"html"}) is False
    assert "naïve" in scanned


@pytest.mark.parametrize("content_type", CONTENT_TYPES)
async def test_a_literal_the_tree_does_not_hold_leaves_the_flat_scan_alone(
    content_type: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        embedded_json_scan, "_decoded_string_literals", lambda literals: frozenset()
    )
    body = json.dumps({"a": "\u00e9"})
    assert await _is_threat(_body(content_type, body), {"html"}) is False


def test_literals_decode_together_or_one_by_one_when_the_strict_parse_refuses() -> None:
    together = embedded_json_scan._decoded_string_literals(["a\\u00e9", "b\\n"])
    assert together == {"a\u00e9", "b\n"}
    one_by_one = embedded_json_scan._decoded_string_literals(["a\\u00e9", "b\nc\\n"])
    assert one_by_one == {"a\u00e9", "b\nc\n"}
