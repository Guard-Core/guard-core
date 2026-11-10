import json

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_PROBE = "${7*7}"


def _request(surface: str) -> SyncMockGuardRequest:
    if surface == "query":
        return SyncMockGuardRequest(path="/x", query_params={"q": _PROBE})
    if surface == "path":
        return SyncMockGuardRequest(path=f"/x/{_PROBE}", query_params={})
    if surface == "header":
        return SyncMockGuardRequest(path="/x", headers={"x-probe": _PROBE})
    if surface == "json":
        body = json.dumps({"q": _PROBE}).encode()
        content_type = "application/json"
    elif surface == "form":
        body = f"q={_PROBE}".encode()
        content_type = "application/x-www-form-urlencoded"
    else:
        body = _PROBE.encode()
        content_type = "text/plain"
    return SyncMockGuardRequest(
        path="/x",
        method="POST",
        body_content=body,
        headers={"content-type": content_type, "content-length": str(len(body))},
    )


@pytest.mark.parametrize("surface", ["query", "path", "header", "json", "form", "text"])
def test_the_brace_probe_is_cmd_injection_and_template_on_every_surface(
    surface: str,
) -> None:
    result = detect_penetration_attempt(
        _request(surface), SyncSecurityConfig(enable_redis=False)
    )

    assert sorted(result.threat_categories) == ["cmd_injection", "template"]


@pytest.mark.parametrize("surface", ["query", "path", "header", "json", "form", "text"])
def test_the_brace_probe_blocks_with_only_cmd_injection_enabled(
    surface: str,
) -> None:
    config = SyncSecurityConfig(
        enable_redis=False, enabled_detection_categories=frozenset({"cmd_injection"})
    )

    result = detect_penetration_attempt(_request(surface), config)

    assert result.is_threat is True
