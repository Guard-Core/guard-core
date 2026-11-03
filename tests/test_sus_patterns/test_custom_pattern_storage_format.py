import json
import logging
from collections.abc import Sequence
from typing import Any

import pytest

from guard_core.handlers import _redis_handler_support as redis_types
from guard_core.handlers.redis_handler import RedisHandlerBase
from guard_core.handlers.suspatterns_handler import (
    SusPatternsManager,
    sus_patterns_handler,
)
from guard_core.models import SecurityConfig

COMMA_PATTERN = r"\bacct\d{1,3}\b"
LEGACY = ("patterns", "custom")
LISTED = ("patterns", "custom_list")


class _FakeRedis(RedisHandlerBase):
    def __init__(self, **stored: str) -> None:
        self.values: dict[tuple[str, str], str] = {}
        if "legacy" in stored:
            self.values[LEGACY] = stored["legacy"]
        if "listed" in stored:
            self.values[LISTED] = stored["listed"]
        self.atomic_writes = 0

    async def set_key(
        self,
        namespace: str,
        key: str,
        value: redis_types.RedisValue,
        ttl: int | None = None,
    ) -> bool | None:
        raise AssertionError("the custom patterns are written in one MULTI")

    async def get_key(self, namespace: str, key: str) -> str | None:
        return self.values.get((namespace, key))

    async def get_many(self, pairs: Sequence[tuple[str, str]]) -> list[str | None]:
        return [self.values.get(pair) for pair in pairs]

    async def write_atomically(
        self,
        *,
        sets: Sequence[tuple[str, str, redis_types.RedisValue, int | None]] = (),
        deletes: Sequence[tuple[str, str]] = (),
        increment: tuple[str, str] | None = None,
    ) -> None:
        self.atomic_writes += 1
        for namespace, key, value, _ttl in sets:
            assert isinstance(value, str)
            self.values[(namespace, key)] = value


def _v440_reads(stored: str | None) -> list[str]:
    return stored.split(",") if stored else []


def _v440_writes(patterns: set[str]) -> str:
    return ",".join(patterns)


@pytest.fixture(autouse=True)
async def clean_registry() -> object:
    sus_patterns_handler.configure(SecurityConfig())
    sus_patterns_handler.redis_handler = None
    await SusPatternsManager.reset()
    yield
    await SusPatternsManager.reset()
    sus_patterns_handler.redis_handler = None


async def _restore(**stored: str) -> set[str]:
    sus_patterns_handler.configure(SecurityConfig())
    fake: Any = _FakeRedis(**stored)
    await sus_patterns_handler.initialize_redis(fake)
    return set(sus_patterns_handler.custom_patterns)


async def test_the_legacy_key_keeps_the_comma_joined_value_a_v440_engine_reads() -> (
    None
):
    fake = _FakeRedis()
    sus_patterns_handler.redis_handler = fake

    for pattern in (r"zeta\d{2,4}", "alpha", COMMA_PATTERN):
        assert await SusPatternsManager.add_pattern(pattern, custom=True)

    patterns = {r"zeta\d{2,4}", "alpha", COMMA_PATTERN}
    assert set(fake.values[LEGACY].split(",")) == set(_v440_writes(patterns).split(","))
    assert fake.values[LEGACY] == ",".join(sorted(patterns))
    assert json.loads(fake.values[LISTED]) == sorted(patterns)


async def test_a_pattern_with_a_comma_survives_the_store_and_restore() -> None:
    fake = _FakeRedis()
    sus_patterns_handler.redis_handler = fake
    assert await SusPatternsManager.add_pattern(COMMA_PATTERN, custom=True)

    await SusPatternsManager.reset()

    assert await _restore(**_both(fake)) == {COMMA_PATTERN}


def _both(fake: _FakeRedis) -> dict[str, str]:
    return {"legacy": fake.values[LEGACY], "listed": fake.values[LISTED]}


async def test_a_v440_engine_splits_a_comma_pattern_as_it_splits_its_own() -> None:
    fake = _FakeRedis()
    sus_patterns_handler.redis_handler = fake
    assert await SusPatternsManager.add_pattern(COMMA_PATTERN, custom=True)

    assert fake.values[LEGACY] == _v440_writes({COMMA_PATTERN})
    assert _v440_reads(fake.values[LEGACY]) == [r"\bacct\d{1", r"3}\b"]


async def test_both_keys_are_written_in_one_atomic_write_per_change() -> None:
    fake = _FakeRedis()
    sus_patterns_handler.redis_handler = fake

    await SusPatternsManager.add_pattern("alpha", custom=True)
    await SusPatternsManager.add_pattern("beta", custom=True)
    assert await SusPatternsManager.remove_pattern("alpha", custom=True)

    assert fake.atomic_writes == 3
    assert fake.values[LEGACY] == "beta"
    assert json.loads(fake.values[LISTED]) == ["beta"]


async def test_the_list_is_read_when_it_agrees_with_the_legacy_key() -> None:
    legacy = ",".join(["alpha", COMMA_PATTERN])

    restored = await _restore(
        legacy=legacy, listed=json.dumps([COMMA_PATTERN, "alpha"])
    )

    assert restored == {COMMA_PATTERN, "alpha"}


async def test_agreement_compares_fragment_sets_not_strings() -> None:
    legacy = ",".join(["zeta", COMMA_PATTERN, "alpha"])
    listed = json.dumps(sorted(["zeta", COMMA_PATTERN, "alpha"]))
    assert legacy != ",".join(sorted(["zeta", COMMA_PATTERN, "alpha"]))

    restored = await _restore(legacy=legacy, listed=listed)

    assert restored == {"zeta", COMMA_PATTERN, "alpha"}


async def test_a_v440_add_after_a_new_write_is_seen(
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake = _FakeRedis()
    sus_patterns_handler.redis_handler = fake
    await SusPatternsManager.add_pattern("alpha", custom=True)
    await SusPatternsManager.add_pattern("beta", custom=True)
    await SusPatternsManager.reset()
    fake.values[LEGACY] = _v440_writes({"alpha", "beta", "gamma"})

    with caplog.at_level(logging.WARNING, logger="guard_core.handlers.suspatterns"):
        restored = await _restore(**_both(fake))

    assert restored == {"alpha", "beta", "gamma"}
    assert caplog.text.count("patterns:custom_list") == 1


async def test_a_v440_remove_after_a_new_write_is_seen(
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake = _FakeRedis()
    sus_patterns_handler.redis_handler = fake
    await SusPatternsManager.add_pattern("alpha", custom=True)
    await SusPatternsManager.add_pattern("beta", custom=True)
    await SusPatternsManager.reset()
    fake.values[LEGACY] = _v440_writes({"alpha"})

    with caplog.at_level(logging.WARNING, logger="guard_core.handlers.suspatterns"):
        restored = await _restore(**_both(fake))

    assert restored == {"alpha"}
    assert caplog.text.count("patterns:custom_list") == 1


async def test_a_v440_remove_of_the_last_pattern_empties_the_set() -> None:
    assert await _restore(legacy="", listed=json.dumps(["alpha"])) == set()


async def test_a_v440_add_then_remove_back_to_the_same_set_keeps_the_list() -> None:
    legacy = _v440_writes({COMMA_PATTERN})

    assert await _restore(legacy=legacy, listed=json.dumps([COMMA_PATTERN])) == {
        COMMA_PATTERN
    }


async def test_a_deleted_legacy_key_wins_over_a_stale_list() -> None:
    assert await _restore(listed=json.dumps(["alpha"])) == set()


async def test_the_legacy_comma_joined_value_alone_is_still_read() -> None:
    assert await _restore(legacy="alpha,beta,gamma") == {"alpha", "beta", "gamma"}


@pytest.mark.parametrize("listed", ["alpha", "42", '{"a": 1}', '"alpha"', "[1, 2]"])
async def test_a_list_key_that_is_not_a_json_list_of_strings_is_ignored(
    listed: str, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="guard_core.handlers.suspatterns"):
        restored = await _restore(legacy="alpha,beta", listed=listed)

    assert restored == {"alpha", "beta"}
    assert caplog.text.count("patterns:custom_list") == 1


async def test_an_empty_list_with_an_empty_legacy_value_restores_nothing() -> None:
    assert await _restore(legacy="", listed="[]") == set()


async def test_no_stored_patterns_restore_nothing() -> None:
    assert await _restore() == set()
