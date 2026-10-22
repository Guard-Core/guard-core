import json
from collections.abc import Callable
from urllib.parse import quote, urlencode

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_detection.benign_prompt_corpus import BENIGN_PROMPTS
from tests.test_sus_patterns.test_detection_benchmark import (
    BENIGN_CORPUS,
    MALICIOUS_CORPUS,
)
from tests.test_sync.conftest import SyncMockGuardRequest

_MULTI_VALUE_BENIGN = [
    "limit=5",
    "filter=foo|bar",
    "(?i)select.*from",
    "mode=fulltext&brief=100&format=json&sorted=false",
    "O'Brien",
    "don't or won't",
    "it's 'x' = 'y' in the spec",
    "rock 'n' roll or jazz",
    "or 1=1 is a tautology",
    "please select a plan",
    "../relative",
    "..\\other",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "application/json, text/plain, */*",
    "en-US,en;q=0.9,it;q=0.8",
    "session=abc; theme=dark; lang=en",
    "100% sure & fish = chips",
]
_ATTACKS_FOR_DEPTH = [
    "' OR 1=1--",
    "<script>alert(1)</script>",
    "../../../../etc/passwd",
    "; cat /etc/passwd",
    "1' UNION SELECT password FROM users--",
]
_VALUES = (
    [case.payload for case in MALICIOUS_CORPUS]
    + [case.payload for case in BENIGN_CORPUS[::4]]
    + BENIGN_PROMPTS[::3]
    + _MULTI_VALUE_BENIGN
)
_HEADERS = {"user-agent": "Mozilla/5.0"}
_FIRST_PAIR = ("a", "b")


def _headerable(value: str) -> str:
    return value.replace("\r", " ").replace("\n", " ")


def _query(value: str, tail: bool) -> SyncMockGuardRequest:
    pairs = ([_FIRST_PAIR] if tail else []) + [("q", value)]
    return SyncMockGuardRequest(path="/api", query_params=dict(pairs))


def _form(value: str, tail: bool) -> SyncMockGuardRequest:
    pairs = ([_FIRST_PAIR] if tail else []) + [("q", value)]
    body = urlencode(pairs, errors="surrogateescape").encode()
    return SyncMockGuardRequest(
        path="/api",
        method="POST",
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "content-length": str(len(body)),
        },
        body_content=body,
    )


def _json(value: str, tail: bool) -> SyncMockGuardRequest:
    document = ({_FIRST_PAIR[0]: _FIRST_PAIR[1]} if tail else {}) | {"q": value}
    body = json.dumps(document).encode()
    return SyncMockGuardRequest(
        path="/api",
        method="POST",
        headers={"content-type": "application/json", "content-length": str(len(body))},
        body_content=body,
    )


def _header(value: str, tail: bool) -> SyncMockGuardRequest:
    headers = ({"x-first": "b"} if tail else {}) | {"x-q": _headerable(value)}
    return SyncMockGuardRequest(path="/api", headers={**_HEADERS, **headers})


_SURFACES: dict[str, Callable[[str, bool], SyncMockGuardRequest]] = {
    "query": _query,
    "form": _form,
    "json": _json,
    "header": _header,
}


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


def _verdict(request: SyncMockGuardRequest, config: SecurityConfig) -> tuple:
    result = detect_penetration_attempt(request, config)
    return result.is_threat, sorted(result.threat_categories)


def _differences(surface: str, values: list[str]) -> list[str]:
    config = SecurityConfig(
        enable_redis=False, rate_limit=10_000_000, detection_max_scan_values=2
    )
    build = _SURFACES[surface]
    differing = []
    for value in values:
        walk = _verdict(build(value, False), config)
        remainder = _verdict(build(value, True), config)
        if walk != remainder:
            differing.append(f"{value[:60]!r}: walk {walk} remainder {remainder}")
    return differing


@pytest.mark.parametrize("surface", sorted(_SURFACES))
def test_a_value_after_the_budget_gets_the_verdict_it_gets_in_the_walk(
    surface: str,
) -> None:
    assert _differences(surface, _VALUES) == []


@pytest.mark.parametrize("surface", sorted(_SURFACES))
def test_the_remainder_decodes_as_deep_as_the_walk_does(surface: str) -> None:
    values = []
    for attack in _ATTACKS_FOR_DEPTH:
        encoded = attack
        for _ in range(18):
            encoded = quote(encoded, safe="")
            values.append(encoded)
    assert _differences(surface, values) == []
