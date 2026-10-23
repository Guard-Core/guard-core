import json
import logging
from typing import Any

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.suspatterns_handler import (
    SusPatternsManager,
    sus_patterns_handler,
)

COMMA_PATTERN = r"\bacct\d{1,3}\b"
LEGACY = ("patterns", "custom")
LISTED = ("patterns", "custom_list")


class _FakeRedis:
    def __init__(self, **stored: str) -> None:
        self.values: dict[tuple[str, str], Any] = {}
        if "legacy" in stored:
            self.values[LEGACY] = stored["legacy"]
        if "listed" in stored:
            self.values[LISTED] = stored["listed"]
        self.atomic_writes = 0

    def set_key(self, namespace: str, key: str, value: Any) -> None:
        raise AssertionError("the custom patterns are written in one MULTI")

    def get_key(self, namespace: str, key: str) -> Any:
        return self.values.get((namespace, key))

    def get_many(self, pairs: Any) -> list[Any]:
        return [self.values.get(pair) for pair in pairs]

    def write_atomically(self, *, sets: Any = (), **_: Any) -> None:
        self.atomic_writes += 1
        for namespace, key, value, _ttl in sets:
            self.values[(namespace, key)] = value


def _v440_reads(stored: str | None) -> list[str]:
    return stored.split(",") if stored else []


def _v440_writes(patterns: set[str]) -> str:
    return ",".join(patterns)


@pytest.fixture(autouse=True)
def clean_registry() -> Any:
    sus_patterns_handler.configure(SyncSecurityConfig())
    sus_patterns_handler.redis_handler = None
    SusPatternsManager.reset()
    yield
    SusPatternsManager.reset()
    sus_patterns_handler.redis_handler = None


def _restore(**stored: str) -> set[str]:
    sus_patterns_handler.configure(SyncSecurityConfig())
    sus_patterns_handler.initialize_redis(_FakeRedis(**stored))
    return set(sus_patterns_handler.custom_patterns)


def test_the_legacy_key_keeps_the_comma_joined_value_a_v440_engine_reads() -> None:
    fake = _FakeRedis()
    sus_patterns_handler.redis_handler = fake

    for pattern in (r"zeta\d{2,4}", "alpha", COMMA_PATTERN):
        assert SusPatternsManager.add_pattern(pattern, custom=True)

    patterns = {r"zeta\d{2,4}", "alpha", COMMA_PATTERN}
    assert set(fake.values[LEGACY].split(",")) == set(_v440_writes(patterns).split(","))
    assert fake.values[LEGACY] == ",".join(sorted(patterns))
    assert json.loads(fake.values[LISTED]) == sorted(patterns)


def test_a_pattern_with_a_comma_survives_the_store_and_restore() -> None:
    fake = _FakeRedis()
    sus_patterns_handler.redis_handler = fake
    assert SusPatternsManager.add_pattern(COMMA_PATTERN, custom=True)

    SusPatternsManager.reset()

    assert _restore(**_both(fake)) == {COMMA_PATTERN}


def _both(fake: _FakeRedis) -> dict[str, str]:
    return {"legacy": fake.values[LEGACY], "listed": fake.values[LISTED]}


def test_a_v440_engine_splits_a_comma_pattern_as_it_splits_its_own() -> None:
    fake = _FakeRedis()
    sus_patterns_handler.redis_handler = fake
    assert SusPatternsManager.add_pattern(COMMA_PATTERN, custom=True)

    assert fake.values[LEGACY] == _v440_writes({COMMA_PATTERN})
    assert _v440_reads(fake.values[LEGACY]) == [r"\bacct\d{1", r"3}\b"]


def test_both_keys_are_written_in_one_atomic_write_per_change() -> None:
    fake = _FakeRedis()
    sus_patterns_handler.redis_handler = fake

    SusPatternsManager.add_pattern("alpha", custom=True)
    SusPatternsManager.add_pattern("beta", custom=True)
    assert SusPatternsManager.remove_pattern("alpha", custom=True)

    assert fake.atomic_writes == 3
    assert fake.values[LEGACY] == "beta"
    assert json.loads(fake.values[LISTED]) == ["beta"]


def test_the_list_is_read_when_it_agrees_with_the_legacy_key() -> None:
    legacy = ",".join(["alpha", COMMA_PATTERN])

    restored = _restore(legacy=legacy, listed=json.dumps([COMMA_PATTERN, "alpha"]))

    assert restored == {COMMA_PATTERN, "alpha"}


def test_agreement_compares_fragment_sets_not_strings() -> None:
    legacy = ",".join(["zeta", COMMA_PATTERN, "alpha"])
    listed = json.dumps(sorted(["zeta", COMMA_PATTERN, "alpha"]))
    assert legacy != ",".join(sorted(["zeta", COMMA_PATTERN, "alpha"]))

    restored = _restore(legacy=legacy, listed=listed)

    assert restored == {"zeta", COMMA_PATTERN, "alpha"}


def test_a_v440_add_after_a_new_write_is_seen(
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake = _FakeRedis()
    sus_patterns_handler.redis_handler = fake
    SusPatternsManager.add_pattern("alpha", custom=True)
    SusPatternsManager.add_pattern("beta", custom=True)
    SusPatternsManager.reset()
    fake.values[LEGACY] = _v440_writes({"alpha", "beta", "gamma"})

    with caplog.at_level(
        logging.WARNING, logger="guard_core.sync.handlers.suspatterns"
    ):
        restored = _restore(**_both(fake))

    assert restored == {"alpha", "beta", "gamma"}
    assert caplog.text.count("patterns:custom_list") == 1


def test_a_v440_remove_after_a_new_write_is_seen(
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake = _FakeRedis()
    sus_patterns_handler.redis_handler = fake
    SusPatternsManager.add_pattern("alpha", custom=True)
    SusPatternsManager.add_pattern("beta", custom=True)
    SusPatternsManager.reset()
    fake.values[LEGACY] = _v440_writes({"alpha"})

    with caplog.at_level(
        logging.WARNING, logger="guard_core.sync.handlers.suspatterns"
    ):
        restored = _restore(**_both(fake))

    assert restored == {"alpha"}
    assert caplog.text.count("patterns:custom_list") == 1


def test_a_v440_remove_of_the_last_pattern_empties_the_set() -> None:
    assert _restore(legacy="", listed=json.dumps(["alpha"])) == set()


def test_a_v440_add_then_remove_back_to_the_same_set_keeps_the_list() -> None:
    legacy = _v440_writes({COMMA_PATTERN})

    assert _restore(legacy=legacy, listed=json.dumps([COMMA_PATTERN])) == {
        COMMA_PATTERN
    }


def test_a_deleted_legacy_key_wins_over_a_stale_list() -> None:
    assert _restore(listed=json.dumps(["alpha"])) == set()


def test_the_legacy_comma_joined_value_alone_is_still_read() -> None:
    assert _restore(legacy="alpha,beta,gamma") == {"alpha", "beta", "gamma"}


@pytest.mark.parametrize("listed", ["alpha", "42", '{"a": 1}', '"alpha"', "[1, 2]"])
def test_a_list_key_that_is_not_a_json_list_of_strings_is_ignored(
    listed: str, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(
        logging.WARNING, logger="guard_core.sync.handlers.suspatterns"
    ):
        restored = _restore(legacy="alpha,beta", listed=listed)

    assert restored == {"alpha", "beta"}
    assert caplog.text.count("patterns:custom_list") == 1


def test_an_empty_list_with_an_empty_legacy_value_restores_nothing() -> None:
    assert _restore(legacy="", listed="[]") == set()


def test_no_stored_patterns_restore_nothing() -> None:
    assert _restore() == set()
