import json
from typing import Any

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers.suspatterns_handler import (
    SusPatternsManager,
    sus_patterns_handler,
)

COMMA_PATTERN = r"\bacct\d{1,3}\b"


class _FakeRedis:
    def __init__(self, stored: str | None = None) -> None:
        self.values: dict[tuple[str, str], Any] = {}
        if stored is not None:
            self.values[("patterns", "custom")] = stored

    def set_key(self, namespace: str, key: str, value: Any) -> None:
        self.values[(namespace, key)] = value

    def get_key(self, namespace: str, key: str) -> Any:
        return self.values.get((namespace, key))


@pytest.fixture(autouse=True)
def clean_registry() -> Any:
    sus_patterns_handler.configure(SecurityConfig())
    sus_patterns_handler.redis_handler = None
    SusPatternsManager.reset()
    yield
    SusPatternsManager.reset()
    sus_patterns_handler.redis_handler = None


def _restore(stored: str) -> set[str]:
    sus_patterns_handler.configure(SecurityConfig())
    sus_patterns_handler.initialize_redis(_FakeRedis(stored))
    return set(sus_patterns_handler.custom_patterns)


def test_a_pattern_with_a_comma_survives_the_store_and_restore() -> None:
    fake = _FakeRedis()
    sus_patterns_handler.redis_handler = fake

    assert SusPatternsManager.add_pattern(COMMA_PATTERN, custom=True)

    assert json.loads(fake.values[("patterns", "custom")]) == [COMMA_PATTERN]
    SusPatternsManager.reset()
    assert _restore(fake.values[("patterns", "custom")]) == {COMMA_PATTERN}


def test_several_patterns_are_stored_as_one_sorted_json_list() -> None:
    fake = _FakeRedis()
    sus_patterns_handler.redis_handler = fake

    for pattern in (r"zeta\d{2,4}", "alpha", COMMA_PATTERN):
        assert SusPatternsManager.add_pattern(pattern, custom=True)

    stored = json.loads(fake.values[("patterns", "custom")])
    assert stored == sorted([r"zeta\d{2,4}", "alpha", COMMA_PATTERN])


def test_removing_a_pattern_rewrites_the_json_list() -> None:
    fake = _FakeRedis()
    sus_patterns_handler.redis_handler = fake
    SusPatternsManager.add_pattern("alpha", custom=True)
    SusPatternsManager.add_pattern(COMMA_PATTERN, custom=True)

    assert SusPatternsManager.remove_pattern("alpha", custom=True)

    assert json.loads(fake.values[("patterns", "custom")]) == [COMMA_PATTERN]


def test_the_legacy_comma_joined_value_is_still_read() -> None:
    assert _restore("alpha,beta,gamma") == {"alpha", "beta", "gamma"}


@pytest.mark.parametrize("stored", ["alpha", "42", '{"a": 1}', '"alpha"'])
def test_a_value_that_is_not_a_json_list_of_strings_is_read_as_legacy(
    stored: str,
) -> None:
    restored = _restore(stored)

    assert restored == set(stored.split(","))


def test_an_empty_json_list_restores_nothing() -> None:
    assert _restore("[]") == set()
