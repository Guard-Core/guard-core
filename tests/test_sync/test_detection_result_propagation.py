from typing import Any, cast

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.helpers import detect_penetration_patterns
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.detection_result import DetectionResult
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from guard_core.sync.utils import detect_penetration_attempt


class _FakeRequest:
    def __init__(self, query_params: dict[str, str] | None = None) -> None:
        self.query_params = query_params or {}
        self.headers: dict[str, str] = {}
        self.url_path = "/"
        self.method = "GET"
        self.client_host = "127.0.0.1"
        self.state = type("S", (), {})()

    def body(self) -> bytes:
        return b""


def test_detect_returns_detection_result_for_threat() -> None:
    request = cast(
        SyncGuardRequest, _FakeRequest(query_params={"q": "<script>alert(1)</script>"})
    )
    result = detect_penetration_attempt(request, SyncSecurityConfig())
    assert isinstance(result, DetectionResult)
    assert result.is_threat is True
    assert "xss" in result.threat_categories
    assert result.trigger_info.startswith("Query param 'q'")


def test_detect_returns_detection_result_for_clean_request() -> None:
    request = cast(SyncGuardRequest, _FakeRequest(query_params={"q": "hello world"}))
    result = detect_penetration_attempt(request, SyncSecurityConfig())
    assert isinstance(result, DetectionResult)
    assert result.is_threat is False
    assert result.threat_categories == []
    assert result.trigger_info == ""


def test_detect_populates_threat_scores_from_regex_threat() -> None:
    request = cast(
        SyncGuardRequest, _FakeRequest(query_params={"q": "<script>alert(1)</script>"})
    )
    result = detect_penetration_attempt(request, SyncSecurityConfig())
    assert result.is_threat is True
    assert "xss" in result.threat_scores
    assert result.threat_scores["xss"] >= 0.0


def test_detect_returns_miss_when_body_decode_fails() -> None:
    class _BadBodyRequest(_FakeRequest):
        def body(self) -> bytes:
            raise RuntimeError("body unavailable")

    request: Any = _BadBodyRequest(query_params={"q": "hello"})
    result = detect_penetration_attempt(request, SyncSecurityConfig())
    assert isinstance(result, DetectionResult)
    assert result.is_threat is False


def test_detect_patterns_returns_detection_result_threat() -> None:
    request = cast(
        SyncGuardRequest, _FakeRequest(query_params={"q": "<script>alert(1)</script>"})
    )
    config = SyncSecurityConfig()
    result = detect_penetration_patterns(request, None, config, lambda *_: False)
    assert isinstance(result, DetectionResult)
    assert result.is_threat is True
    assert "xss" in result.threat_categories


def test_detect_patterns_returns_detection_result_bypass() -> None:
    request = cast(
        SyncGuardRequest, _FakeRequest(query_params={"q": "<script>alert(1)</script>"})
    )
    config = SyncSecurityConfig()
    result = detect_penetration_patterns(request, None, config, lambda *_: True)
    assert isinstance(result, DetectionResult)
    assert result.is_threat is False
    assert result.trigger_info == "not_enabled"


def test_detect_patterns_returns_detection_result_disabled_by_decorator() -> None:
    request = cast(SyncGuardRequest, _FakeRequest())
    config = SyncSecurityConfig(enable_penetration_detection=True)
    route_config = RouteConfig()
    route_config.enable_suspicious_detection = False
    result = detect_penetration_patterns(
        request, route_config, config, lambda *_: False
    )
    assert isinstance(result, DetectionResult)
    assert result.is_threat is False
    assert result.trigger_info == "disabled_by_decorator"
