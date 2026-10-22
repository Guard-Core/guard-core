import json
from urllib.parse import quote_plus

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

_HEADERS = {"user-agent": "Mozilla/5.0", "accept": "text/html"}

ATTACKS = [
    "' OR 'x' = 'x",
    '\' OR "x"="x',
    '\' OR "x" = "x',
    "'/**/OR/**/'x' = 'x",
    '\'/**/OR/**/"x"="x',
    "admin'/*",
    "admin' #",
    "admin' /*",
    "' OR 1 = 1",
    "' OR 'a' LIKE 'a",
    "' OR 'a'LIKE'a",
    "' OR 2>1",
    "' OR 2 > 1 --",
    "' OR TRUE--",
    "' OR TRUE --",
    "' OR TRUE #",
    "' oR 'X' = 'x",
    "' Or 1 = 1",
    "' AND 'x' = 'x",
    "' or '' = '",
    '" or "" = "',
    "1' OR '1' = '1",
    "') OR ('a' = 'a",
    "')) OR (('a'='a",
    "'/**/or/**/true--",
]

BENIGN = [
    "O'Brien",
    "don't or won't",
    "it's 'x' = 'y' in the spec",
    "rock 'n' roll or jazz",
    "or 1=1 is a tautology",
    "or 1=1 is a tautology in logic",
    "best running shoes 2026",
    "the user' #1 pick",
    "it's /* not */ code",
    "he said 'yes' or 'no'",
    "either 'a' or 'b' = fine",
    "John's or Mary's = fine",
    "she's got 'x' and 'y' = 2",
    "L'Oreal or Chanel = great",
    "ed's # of cats",
    "o'clock # 5",
    "tom's /* draft */ notes",
    "x = 'a' or True  # default",
    "if name == 'x' or true: pass",
    "name = 'a' or true # fallback to a",
    "a { content: ''; /* clearfix */ }",
    "foo('x'); /* done */",
    "var s = 'a' /* c */;",
    "true or false",
    "a or b = c",
]


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


def _post(body: bytes, content_type: str) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(
        path="/api",
        method="POST",
        headers={
            **_HEADERS,
            "content-type": content_type,
            "content-length": str(len(body)),
        },
        body_content=body,
    )


def _surfaces(value: str) -> dict[str, SyncMockGuardRequest]:
    return {
        "query": SyncMockGuardRequest(
            path="/search", query_params={"q": value}, headers=dict(_HEADERS)
        ),
        "json": _post(json.dumps({"q": value, "n": 1}).encode(), "application/json"),
        "form": _post(
            f"q={quote_plus(value)}".encode(), "application/x-www-form-urlencoded"
        ),
        "header": SyncMockGuardRequest(
            path="/search", headers={**_HEADERS, "x-search": value}
        ),
    }


def _flagged(request: SyncMockGuardRequest) -> bool:
    result = detect_penetration_attempt(request, SecurityConfig())
    return result.is_threat


@pytest.mark.parametrize("surface", ["query", "json", "form", "header"])
@pytest.mark.parametrize("value", ATTACKS)
def test_sqli_tautology_and_truncation_variants_are_flagged(
    value: str, surface: str
) -> None:
    assert _flagged(_surfaces(value)[surface]) is True


@pytest.mark.parametrize("surface", ["query", "json", "form", "header"])
@pytest.mark.parametrize("value", BENIGN)
def test_prose_and_code_near_the_sqli_variants_stays_clean(
    value: str, surface: str
) -> None:
    assert _flagged(_surfaces(value)[surface]) is False


@pytest.mark.parametrize(
    "encoded",
    [
        "%27%20OR%20%27x%27%20%3D%20%27x",
        "%27%20OR%20%22x%22%3D%22x",
        "%27%2F%2A%2A%2FOR%2F%2A%2A%2F%27x%27%20%3D%20%27x",
        "%27%20oR%20%27x%27%20LIKE%20%27x",
        "%27%20OR%20TRUE--",
        "%27%20OR%201%20%3D%201%20--%20",
        "admin%27%20%23",
        "admin%27%2F%2A",
    ],
)
def test_url_encoded_form_field_variants_are_flagged(encoded: str) -> None:
    request = _post(f"q={encoded}".encode(), "application/x-www-form-urlencoded")
    assert _flagged(request) is True
