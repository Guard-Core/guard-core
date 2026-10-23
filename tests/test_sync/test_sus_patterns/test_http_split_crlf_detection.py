import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SyncSecurityConfig())


HTTP_SPLIT_BODIES = [
    pytest.param("\r\nLocation: https://evil.example/", id="crlf_location"),
    pytest.param("\n\n\nSet-Cookie: x=y", id="blankline_set_cookie"),
    pytest.param("\n\tHTTP/1.0 200 OK", id="newline_tab_http"),
    pytest.param("\nHTTP/1.1 500", id="newline_http"),
]


@pytest.mark.parametrize("body", HTTP_SPLIT_BODIES)
def test_http_split_crlf_bodies_fire(body: str) -> None:
    result = sus_patterns_handler.detect(
        content=body, ip_address="203.0.113.9", context="request_body"
    )
    assert result["is_threat"] is True
    assert any(threat.get("category") == "http_split" for threat in result["threats"])


HTTP_SPLIT_BENIGN_BODIES = [
    pytest.param("clean text no split", id="clean_text"),
    pytest.param("Location: https://evil.example/", id="location_no_leading_break"),
]


@pytest.mark.parametrize("body", HTTP_SPLIT_BENIGN_BODIES)
def test_benign_bodies_do_not_fire_http_split(body: str) -> None:
    result = sus_patterns_handler.detect(
        content=body, ip_address="203.0.113.9", context="request_body"
    )
    assert not any(
        threat.get("category") == "http_split" for threat in result["threats"]
    )
