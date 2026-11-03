import json

import pytest

from guard_core._utils.detection_scan import LazyPreview
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
CONTENT_TYPES = ["text/plain", "application/octet-stream"]
MAX_SCANS_FOR_A_BODY_WITHOUT_A_BACKSLASH = 3


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


def _body(content_type: str, payload: bytes) -> MockGuardRequest:
    return MockGuardRequest(
        path="/api",
        method="POST",
        headers={"content-type": content_type, "content-length": str(len(payload))},
        body_content=payload,
    )


def _watch_detect(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    scanned: list[str] = []
    detect = SusPatternsManager.detect

    async def counting_detect(
        self: SusPatternsManager,
        content: str,
        ip_address: str,
        context: str = "unknown",
        correlation_id: str | None = None,
        enabled_categories: set[str] | None = None,
        *,
        content_preview: str | LazyPreview | None = None,
    ) -> DetectionResult:
        if context.startswith("request_body"):
            scanned.append(content)
        return await detect(
            self,
            content,
            ip_address,
            context,
            correlation_id,
            enabled_categories,
            content_preview=content_preview,
        )

    monkeypatch.setattr(SusPatternsManager, "detect", counting_detect)
    return scanned


async def _is_threat(
    request: MockGuardRequest, route_config: RouteConfig | None = None
) -> bool:
    config = SecurityConfig(enable_redis=False, rate_limit=10_000_000)
    return (await detect_penetration_attempt(request, config, route_config)).is_threat


@pytest.mark.parametrize("content_type", CONTENT_TYPES)
async def test_an_undeclared_body_without_a_backslash_is_scanned_as_one_text(
    content_type: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [
        {"id": index, "name": f"Mary {index}", "tag": f"t{index}"}
        for index in range(60)
    ]
    scanned = _watch_detect(monkeypatch)
    assert (
        await _is_threat(_body(content_type, json.dumps({"rows": rows}).encode()))
        is False
    )
    assert len(scanned) <= MAX_SCANS_FOR_A_BODY_WITHOUT_A_BACKSLASH


@pytest.mark.parametrize("content_type", CONTENT_TYPES)
async def test_an_undeclared_body_is_walked_only_through_its_escaped_literals(
    content_type: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [{"id": index, "name": f"Mary {index}"} for index in range(60)]
    payload = {"rows": rows, "note": "first line\nsecond line", "q": 'say "hi" there'}
    scanned = _watch_detect(monkeypatch)
    assert await _is_threat(_body(content_type, json.dumps(payload).encode())) is False
    assert "first line\nsecond line" in scanned
    assert 'say "hi" there' in scanned
    assert not any(text in ("Mary 7", "7") for text in scanned)
    assert len(scanned) <= MAX_SCANS_FOR_A_BODY_WITHOUT_A_BACKSLASH + 2


@pytest.mark.parametrize("content_type", CONTENT_TYPES)
async def test_an_escaped_payload_among_many_plain_values_is_found(
    content_type: str,
) -> None:
    rows = [{"id": index, "name": f"Mary {index}"} for index in range(1000)]
    body = json.dumps({"rows": rows, "q": "@@PAYLOAD@@"}).replace(
        "@@PAYLOAD@@", XSS_ESCAPED
    )
    assert await _is_threat(_body(content_type, body.encode())) is True


@pytest.mark.parametrize("content_type", CONTENT_TYPES)
async def test_a_backslash_heavy_benign_body_is_clean(content_type: str) -> None:
    rows = [
        f"line {index}\nsecond line {index}" if index % 2 else f'say "hello {index}"'
        for index in range(400)
    ]
    assert (
        await _is_threat(_body(content_type, json.dumps({"rows": rows}).encode()))
        is False
    )


@pytest.mark.parametrize("exclusion", [{"html"}, {"html": {"xss"}}])
async def test_an_excluded_body_field_of_an_undeclared_body_is_not_walked(
    exclusion: set[str] | dict[str, set[str]],
) -> None:
    route_config = RouteConfig()
    route_config.excluded_detection_body_fields = exclusion
    inner = json.dumps({"q": "@@PAYLOAD@@"}).replace("@@PAYLOAD@@", XSS_ESCAPED)
    body = json.dumps({"html": inner})
    other = body.replace('"html"', '"other"')
    assert await _is_threat(_body("text/plain", body.encode()), route_config) is False
    assert await _is_threat(_body("text/plain", other.encode()), route_config) is True
