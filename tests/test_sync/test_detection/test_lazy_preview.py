import json
from typing import Any
from unittest.mock import patch

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils import body_content_scan, penetration_detection
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest


def _post(content_type: str, body: str) -> SyncMockGuardRequest:
    raw = body.encode()
    return SyncMockGuardRequest(
        method="POST",
        path="/s/ok",
        query_params={"q": "red shoes"},
        headers={
            "content-type": content_type,
            "content-length": str(len(raw)),
            "x-note": "blue boots",
        },
        body_content=raw,
    )


BENIGN = {
    "query": SyncMockGuardRequest(path="/s/ok", query_params={"q": "red shoes"}),
    "header": SyncMockGuardRequest(path="/s", headers={"x-note": "blue boots"}),
    "json": _post("application/json", json.dumps({"a": "hello", "b": ["x"]})),
    "blob": _post("text/plain", "plain words"),
    "form": _post("application/x-www-form-urlencoded", "a=1&b=two"),
}


class _Spies:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def wrap(self, name: str, original: Any) -> Any:
        def spy(*args: Any, **kwargs: Any) -> Any:
            self.calls.append(name)
            return original(*args, **kwargs)

        return spy


@pytest.mark.parametrize("surface", sorted(BENIGN))
def test_a_benign_value_never_builds_its_display_preview(surface: str) -> None:
    spies = _Spies()
    with (
        patch.object(
            body_content_scan,
            "_non_sensitive_display",
            spies.wrap("display", body_content_scan._non_sensitive_display),
        ),
        patch.object(
            body_content_scan,
            "redact_blob_for_display",
            spies.wrap("blob", body_content_scan.redact_blob_for_display),
        ),
        patch.object(
            penetration_detection,
            "redact_url_for_display",
            spies.wrap("url", penetration_detection.redact_url_for_display),
        ),
    ):
        result = detect_penetration_attempt(
            BENIGN[surface], SyncSecurityConfig(enable_redis=False)
        )

    assert result.is_threat is False
    assert [call for call in spies.calls if call != "blob"] == []
    assert spies.calls.count("blob") <= 1


@pytest.mark.parametrize(
    ("request_", "secret_name"),
    [
        (
            SyncMockGuardRequest(
                path="/s", query_params={"note": "<script>x</script>"}
            ),
            None,
        ),
        (
            SyncMockGuardRequest(
                path="/s", query_params={"id_token": "<script>x</script>"}
            ),
            "id_token",
        ),
        (_post("text/plain", "<script>alert(1)</script>"), None),
    ],
)
def test_a_threat_still_reports_a_preview(
    request_: SyncMockGuardRequest,
    secret_name: str | None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    result = detect_penetration_attempt(
        request_, SyncSecurityConfig(enable_redis=False)
    )

    assert result.is_threat is True
    assert "Potential attack detected" in caplog.text
    if secret_name is not None:
        assert "<script>x</script>" not in caplog.text
