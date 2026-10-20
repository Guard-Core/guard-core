import json
from collections.abc import Callable

import pytest

from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

CODE_TWINS = [
    ("time.sleep(1)", "time.sleep(0.5)"),
    ("await asyncio.sleep(1)", "await asyncio.sleep(0.25)"),
    ("Thread.sleep(500)", "Thread.sleep(0.5)"),
    ("sleep(2)", "sleep(1.5)"),
    ("os.sleep(5)", "os.sleep(0.5)"),
    ("time.sleep( 3 )", "time.sleep( 0.3 )"),
    ("sleep(1); // wait", "sleep(0.1); // wait"),
    ("for i in range(3): time.sleep(2)", "for i in range(3): time.sleep(0.2)"),
    ("def wait():\n    time.sleep(1)\n", "def wait():\n    time.sleep(0.75)\n"),
    ("retry after sleep(10) seconds", "retry after sleep(2.5) seconds"),
]
ATTACK_TWINS = [
    ("1 AND SLEEP(2)", "1 AND SLEEP(2.5)"),
    ("1' AND pg_sleep(1)--", "1' AND pg_sleep(0.5)--"),
    ("1 or sleep(3)#", "1 or sleep(0.3)#"),
    ("x');select sleep(2);--", "x');select sleep(0.2);--"),
]


def _json_body(value: str) -> bytes:
    return json.dumps({"a": value}).encode()


def _post(content_type: str, body: bytes) -> MockGuardRequest:
    return MockGuardRequest(
        method="POST",
        path="/x",
        headers={"content-type": content_type, "content-length": str(len(body))},
        body_content=body,
    )


SURFACES: dict[str, Callable[[str], MockGuardRequest]] = {
    "query": lambda value: MockGuardRequest(path="/x", query_params={"q": value}),
    "json_body": lambda value: _post("application/json", _json_body(value)),
    "text_body": lambda value: _post("text/plain", value.encode()),
}


@pytest.fixture(autouse=True)
def _force_enhanced_detection_singleton() -> None:
    sus_patterns_handler.configure(SecurityConfig())


async def _flagged(surface: str, value: str) -> bool:
    config = SecurityConfig(enable_redis=False, rate_limit=1000)
    result = await detect_penetration_attempt(SURFACES[surface](value), config)
    return result.is_threat


@pytest.mark.parametrize("surface", SURFACES)
@pytest.mark.parametrize(("integer", "decimal"), CODE_TWINS + ATTACK_TWINS)
async def test_a_decimal_delay_is_flagged_exactly_when_its_integer_twin_is(
    surface: str, integer: str, decimal: str
) -> None:
    assert await _flagged(surface, decimal) is await _flagged(surface, integer)


@pytest.mark.parametrize("surface", SURFACES)
@pytest.mark.parametrize(("integer", "decimal"), ATTACK_TWINS)
async def test_every_sleep_attack_is_flagged_with_an_integer_and_a_decimal_delay(
    surface: str, integer: str, decimal: str
) -> None:
    assert await _flagged(surface, integer) is True
    assert await _flagged(surface, decimal) is True
