import json
from collections.abc import Callable
from urllib.parse import urlencode

import pytest

from guard_core._utils.detection_scan import LazyPreview
from guard_core.handlers.suspatterns_handler import (
    DetectionResult,
    SusPatternsManager,
    sus_patterns_handler,
)
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

ATTACK = "' OR 1=1--"
DEPTHS = [32, 64, 128, 256, 512, 600, 1500, 3000]


def _nested_json(depth: int) -> str:
    return '{"a":' * depth + json.dumps("hello") + "}" * depth


def _query(nested: str) -> MockGuardRequest:
    return MockGuardRequest(path="/api", query_params={"q": nested, "z": ATTACK})


def _form(nested: str) -> MockGuardRequest:
    body = urlencode([("q", nested), ("z", ATTACK)]).encode()
    return MockGuardRequest(
        path="/api",
        method="POST",
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "content-length": str(len(body)),
        },
        body_content=body,
    )


def _header(nested: str) -> MockGuardRequest:
    return MockGuardRequest(
        path="/api",
        headers={"user-agent": "Mozilla/5.0", "x-q": nested, "x-z": ATTACK},
    )


def _json_entry(nested: str) -> MockGuardRequest:
    body = json.dumps({"q": nested, "z": ATTACK}).encode()
    return MockGuardRequest(
        path="/api",
        method="POST",
        headers={"content-type": "application/json", "content-length": str(len(body))},
        body_content=body,
    )


def _json_array_leaf(nested: str) -> MockGuardRequest:
    body = json.dumps({"items": [nested, ATTACK]}).encode()
    return MockGuardRequest(
        path="/api",
        method="POST",
        headers={"content-type": "application/json", "content-length": str(len(body))},
        body_content=body,
    )


def _undeclared(content_type: str) -> Callable[[str], MockGuardRequest]:
    def build(nested: str) -> MockGuardRequest:
        body = json.dumps({"q": nested, "z": ATTACK}).encode()
        return MockGuardRequest(
            path="/api",
            method="POST",
            headers={"content-type": content_type, "content-length": str(len(body))},
            body_content=body,
        )

    return build


SURFACES: dict[str, tuple[Callable[[str], MockGuardRequest], str]] = {
    "query": (_query, "Query param 'z'"),
    "form": (_form, "Request body field 'z'"),
    "header": (_header, "Header 'x-z'"),
    "json": (_json_entry, "Request body field 'z'"),
    "json_array_leaf": (_json_array_leaf, "Request body field 'items'"),
    "text_plain": (_undeclared("text/plain"), "Request body"),
    "octet_stream": (_undeclared("application/octet-stream"), "Request body"),
}
# An embedded value scans each nested level once, and a level that repeats a key
# or a leaf is scanned once: the budget is never used up by the nesting, so the
# later item is reached directly at every depth, on every surface.
MAX_SCANNED_VALUES_FOR_ONE_NESTED_VALUE = 20


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


@pytest.mark.parametrize("depth", DEPTHS)
@pytest.mark.parametrize("surface", sorted(SURFACES))
async def test_a_nested_json_value_cannot_use_up_the_budget_before_a_later_item(
    surface: str, depth: int
) -> None:
    build, direct_text = SURFACES[surface]
    nested = _nested_json(depth)
    config = SecurityConfig(enable_redis=False, rate_limit=10_000_000)
    result = await detect_penetration_attempt(build(nested), config)
    assert result.is_threat is True
    assert direct_text in (result.trigger_info or "")


@pytest.mark.parametrize("depth", DEPTHS)
@pytest.mark.parametrize("surface", sorted(SURFACES))
async def test_a_nested_json_value_is_scanned_once_per_distinct_text(
    surface: str, depth: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    build, _direct_text = SURFACES[surface]
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
    config = SecurityConfig(enable_redis=False, rate_limit=10_000_000)
    await detect_penetration_attempt(build(_nested_json(depth)), config)
    assert len(scanned) <= MAX_SCANNED_VALUES_FOR_ONE_NESTED_VALUE


@pytest.mark.parametrize("depth", [64, 512])
async def test_a_nested_json_value_with_distinct_keys_is_scanned_once_per_level(
    depth: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    nested = "".join(f'{{"k{level}":' for level in range(depth))
    nested += json.dumps("hello") + "}" * depth
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
    config = SecurityConfig(enable_redis=False, rate_limit=10_000_000)
    result = await detect_penetration_attempt(_query(nested), config)
    assert result.is_threat is True
    assert len(scanned) <= depth + MAX_SCANNED_VALUES_FOR_ONE_NESTED_VALUE
