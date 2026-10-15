import base64
import json

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync._utils.body_content_scan import _header_items_to_scan
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_CONFIG = SecurityConfig()


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _session_jwt() -> str:
    claims = {
        "sub": "3f2c1b9e-8a47-4d2e-9c1f-5b6a7d8e9f01",
        "name": "Jane Doe (Acme)",
        "email": "jane.doe@example.com",
        "roles": ["admin"],
        "iat": 1792000000,
        "exp": 1792000900,
    }
    return ".".join(
        [
            _b64url(json.dumps({"alg": "ES256", "typ": "JWT"}).encode()),
            _b64url(json.dumps(claims).encode()),
            _b64url(bytes(range(64))),
        ]
    )


def test_cookie_header_is_split_into_pairs() -> None:
    headers = {"Accept": "text/html", "Cookie": "a=1;  b=2;;\r\nc=3"}
    assert list(_header_items_to_scan(headers)) == [
        ("Accept", "text/html"),
        ("Cookie", "a=1"),
        ("Cookie", "b=2"),
        ("Cookie", "\r\nc=3"),
    ]


def test_logged_in_cookie_header_is_not_a_threat() -> None:
    cookie = f"session={_session_jwt()}; theme=system; _ga=GA1.1.123456789.1792000000"
    request = SyncMockGuardRequest(headers={"Cookie": cookie})
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is False


@pytest.mark.parametrize(
    "cookie",
    [
        pytest.param("theme=dark; q=<script>alert(1)</script>", id="xss"),
        pytest.param("theme=dark; id=1' OR 1=1--", id="sqli"),
        pytest.param("theme=dark;\r\nSet-Cookie: admin=1", id="crlf"),
    ],
)
def test_attack_in_one_cookie_is_still_detected(cookie: str) -> None:
    request = SyncMockGuardRequest(headers={"Cookie": cookie})
    result = detect_penetration_attempt(request, _CONFIG)
    assert result.is_threat is True
