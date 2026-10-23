import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

OPENERS = [
    "<script>alert(1)",
    "<script>alert(1)//",
    "<ScRiPt>alert(document.domain)",
    "<script >alert(1)",
    "<script/src=//e.example/x.js>",
    '"><script>alert(1)',
    "x<script>alert(1)",
    "<script>confirm(1)</script",
    "<script>prompt(1)",
    "<script>fetch('/x')",
]

BENIGN = [
    "The `<script>` tag loads external JavaScript resources.",
    "<script> is the tag name",
    "the scripts folder",
    "a <scripted> element name",
    "JavaScript is a scripting language",
    "<description>script writers</description>",
]


@pytest.mark.parametrize("value", OPENERS)
def test_script_opener_without_closing_tag_is_xss(value: str) -> None:
    request = SyncMockGuardRequest(path="/s", query_params={"q": value})

    result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is True
    assert "xss" in result.threat_categories


@pytest.mark.parametrize("value", OPENERS)
def test_script_opener_in_json_body_is_xss(value: str) -> None:
    import json

    body = json.dumps({"note": value}).encode()
    request = SyncMockGuardRequest(
        method="POST",
        path="/s",
        headers={"content-type": "application/json", "content-length": str(len(body))},
        body_content=body,
    )

    result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is True


@pytest.mark.parametrize("value", BENIGN)
def test_script_word_prose_stays_clean(value: str) -> None:
    request = SyncMockGuardRequest(path="/s", query_params={"q": value})

    result = detect_penetration_attempt(request, SyncSecurityConfig())

    assert result.is_threat is False
