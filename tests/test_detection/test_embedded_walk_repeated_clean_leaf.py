import json

from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

ATTACK = "' OR 1=1--"


async def _is_threat(query_value: str) -> bool:
    request = MockGuardRequest(path="/api", query_params={"q": query_value})
    config = SecurityConfig(enable_redis=False, rate_limit=10_000_000)
    return (await detect_penetration_attempt(request, config)).is_threat


async def test_a_repeated_clean_leaf_in_an_embedded_value_stays_clean() -> None:
    assert await _is_threat(json.dumps({"k": ["hello", "hello", "hello"]})) is False


async def test_a_repeated_leaf_in_an_embedded_value_still_flags_the_attack() -> None:
    assert await _is_threat(json.dumps({"k": ["hello", "hello", ATTACK]})) is True
