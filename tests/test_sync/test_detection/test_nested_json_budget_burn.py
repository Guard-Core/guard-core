import json
from collections.abc import Callable
from urllib.parse import urlencode

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest

ATTACK = "' OR 1=1--"
DEPTHS = [600, 1500, 3000]


def _nested_json(depth: int) -> str:
    return '{"a":' * depth + json.dumps("hello") + "}" * depth


def _query(nested: str) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(path="/api", query_params={"q": nested, "z": ATTACK})


def _form(nested: str) -> SyncMockGuardRequest:
    body = urlencode([("q", nested), ("z", ATTACK)]).encode()
    return SyncMockGuardRequest(
        path="/api",
        method="POST",
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "content-length": str(len(body)),
        },
        body_content=body,
    )


def _header(nested: str) -> SyncMockGuardRequest:
    return SyncMockGuardRequest(
        path="/api",
        headers={"user-agent": "Mozilla/5.0", "x-q": nested, "x-z": ATTACK},
    )


def _json_entry(nested: str) -> SyncMockGuardRequest:
    body = json.dumps({"q": nested, "z": ATTACK}).encode()
    return SyncMockGuardRequest(
        path="/api",
        method="POST",
        headers={"content-type": "application/json", "content-length": str(len(body))},
        body_content=body,
    )


SURFACES: dict[str, tuple[Callable[[str], SyncMockGuardRequest], str, str]] = {
    "query": (_query, "Remaining query params", "Query param 'z'"),
    "form": (_form, "Remaining form fields", "Request body field 'z'"),
    "header": (_header, "Remaining headers", "Header 'x-z'"),
    "json": (_json_entry, "", "Request body field 'z'"),
}


# A JSON body entry is scanned in the "request_body" context, which skips the
# embedded-JSON walk, so it never fans out and is caught on its own key. Elsewhere
# the walk fans out only when the interpreter's json parser accepts the depth
# (3.10 stops near 990 levels and scans the value as text instead).
def _walk_fans_out(nested: str) -> bool:
    try:
        json.loads(nested)
    except RecursionError:
        return False
    return True


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


@pytest.mark.parametrize("depth", DEPTHS)
@pytest.mark.parametrize("surface", sorted(SURFACES))
def test_a_nested_json_value_cannot_use_up_the_budget_before_a_later_item(
    surface: str, depth: int
) -> None:
    build, remainder_text, direct_text = SURFACES[surface]
    nested = _nested_json(depth)
    config = SecurityConfig(enable_redis=False, rate_limit=10_000_000)
    result = detect_penetration_attempt(build(nested), config)
    assert result.is_threat is True
    fans_out = remainder_text and _walk_fans_out(nested)
    assert (remainder_text if fans_out else direct_text) in (result.trigger_info or "")
