import json
import logging
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

import pytest

from guard_core._dynamic_rules import (
    dump_last_known_rules_snapshot,
    dump_legacy_last_known_rules_snapshot,
)
from guard_core.models import DynamicRules, SyncSecurityConfig
from guard_core.sync.handlers._dynamic_rule_persistence import (
    DYNAMIC_RULES_REDIS_NAMESPACE,
    LAST_KNOWN_RULES_FULL_KEY,
    LAST_KNOWN_RULES_KEY,
)
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.handlers.redis_handler import RedisHandlerBase

MANAGER_LOGGER = "guard_core.sync.handlers.dynamic_rule"

# The rule fields v4.4.0's strict snapshot model accepts (v4.4.0
# `_dynamic_rules.py:15-71`): every DynamicRules field but the two 5.0.0 adds.
V440_RULE_FIELDS = frozenset(
    DynamicRules.model_fields.keys() - {"emergency_whitelist_only"}
)
V440_SNAPSHOT_KEYS = frozenset({"schema_version", "rules"})


def _rules(**kwargs: object) -> DynamicRules:
    base: dict[str, object] = {
        "rule_id": "fleet-rule",
        "version": 1,
        "timestamp": datetime(2026, 1, 1, tzinfo=timezone.utc),
    }
    base.update(kwargs)
    return DynamicRules.model_validate(base)


class _DictRedis(RedisHandlerBase):
    def __init__(self) -> None:
        super().__init__(SyncSecurityConfig())
        self.store: dict[tuple[str, str], str] = {}
        self.set_keys: list[str] = []

    def get_key(self, namespace: str, key: str) -> str | None:
        return self.store.get((namespace, key))

    def set_key(
        self, namespace: str, key: str, value: object, ttl: int | None = None
    ) -> bool:
        self.set_keys.append(key)
        self.store[(namespace, key)] = str(value)
        return True

    def delete(self, namespace: str, key: str) -> int:
        return int(self.store.pop((namespace, key), None) is not None)


LEGACY = (DYNAMIC_RULES_REDIS_NAMESPACE, LAST_KNOWN_RULES_KEY)
FULL = (DYNAMIC_RULES_REDIS_NAMESPACE, LAST_KNOWN_RULES_FULL_KEY)


@pytest.fixture(autouse=True)
def reset_singleton() -> Iterator[None]:
    DynamicRuleManager._instance = None
    yield
    DynamicRuleManager._instance = None


def _manager(
    redis: _DictRedis | None, cache_path: Path | None = None
) -> DynamicRuleManager:
    manager = DynamicRuleManager(
        SyncSecurityConfig(dynamic_rules_cache_path=cache_path)
    )
    if redis is not None:
        manager.initialize_redis(redis)
    return manager


def test_legacy_snapshot_holds_only_what_v440_parses() -> None:
    payload = json.loads(
        dump_legacy_last_known_rules_snapshot(_rules(emergency_whitelist_only=False))
    )
    assert set(payload) == V440_SNAPSHOT_KEYS
    assert set(payload["rules"]) == V440_RULE_FIELDS


def test_full_snapshot_keeps_ownership_and_the_new_field() -> None:
    payload = json.loads(
        dump_last_known_rules_snapshot(
            _rules(emergency_whitelist_only=False), ["203.0.113.7"], ["p"]
        )
    )
    assert payload["owned"] == {"bans": ["203.0.113.7"], "patterns": ["p"]}
    assert payload["rules"]["emergency_whitelist_only"] is False


def test_persist_writes_the_legacy_key_and_the_full_key() -> None:
    redis = _DictRedis()
    manager = _manager(redis)
    manager._owned_bans = ["203.0.113.7"]
    manager._persist_last_known_rules(_rules(emergency_whitelist_only=False))
    legacy = json.loads(redis.store[LEGACY])
    full = json.loads(redis.store[FULL])
    assert set(legacy) == V440_SNAPSHOT_KEYS
    assert set(legacy["rules"]) == V440_RULE_FIELDS
    assert full["owned"]["bans"] == ["203.0.113.7"]
    assert full["rules"]["emergency_whitelist_only"] is False
    assert redis.set_keys == [
        LAST_KNOWN_RULES_KEY,
        LAST_KNOWN_RULES_FULL_KEY,
    ]


def test_persist_writes_the_legacy_file_and_the_full_file(
    tmp_path: Path,
) -> None:
    cache = tmp_path / "rules.json"
    manager = _manager(None, cache)
    manager._persist_last_known_rules(_rules(emergency_whitelist_only=False))
    assert set(json.loads(cache.read_text())["rules"]) == V440_RULE_FIELDS
    full = json.loads((tmp_path / "rules.json.full").read_text())
    assert full["rules"]["emergency_whitelist_only"] is False


def test_a_full_snapshot_that_agrees_is_used_whole() -> None:
    redis = _DictRedis()
    writer = _manager(redis)
    writer._owned_bans = ["203.0.113.7"]
    writer._persist_last_known_rules(_rules(emergency_whitelist_only=False))
    DynamicRuleManager._instance = None
    reader = _manager(redis)
    rules = reader._load_last_known_rules()
    assert rules is not None
    assert rules.emergency_whitelist_only is False
    assert reader._restored_ownership == (["203.0.113.7"], [])


def test_a_legacy_write_after_a_full_write_wins_with_one_log_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    redis = _DictRedis()
    writer = _manager(redis)
    writer._owned_bans = ["203.0.113.7"]
    writer._persist_last_known_rules(_rules(version=1))
    redis.store[LEGACY] = dump_legacy_last_known_rules_snapshot(_rules(version=2))
    DynamicRuleManager._instance = None
    reader = _manager(redis)
    with caplog.at_level(logging.DEBUG, logger=MANAGER_LOGGER):
        rules = reader._load_last_known_rules()
    assert rules is not None
    assert rules.version == 2
    assert reader._restored_ownership == ([], [])
    assert [r.levelname for r in caplog.records] == ["WARNING"]
    assert "differs from the legacy snapshot" in caplog.records[0].getMessage()


def test_an_unusable_full_snapshot_falls_back_to_legacy_with_one_log_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    redis = _DictRedis()
    redis.store[LEGACY] = dump_legacy_last_known_rules_snapshot(_rules(version=4))
    redis.store[FULL] = "{not json"
    reader = _manager(redis)
    with caplog.at_level(logging.DEBUG, logger=MANAGER_LOGGER):
        rules = reader._load_last_known_rules()
    assert rules is not None
    assert rules.version == 4
    assert [r.levelname for r in caplog.records] == ["WARNING"]
    assert "is unusable" in caplog.records[0].getMessage()


def test_a_full_snapshot_without_a_legacy_one_is_not_used() -> None:
    redis = _DictRedis()
    redis.store[FULL] = dump_last_known_rules_snapshot(_rules(), [], [])
    reader = _manager(redis)
    assert reader._load_last_known_rules() is None


def test_clear_removes_both_keys_and_both_files(tmp_path: Path) -> None:
    redis = _DictRedis()
    cache = tmp_path / "rules.json"
    manager = _manager(redis, cache)
    manager._persist_last_known_rules(_rules())
    manager._clear_last_known_rules()
    assert redis.store == {}
    assert list(tmp_path.iterdir()) == []


def test_purge_takes_the_owned_patterns_from_the_full_snapshot() -> None:
    redis = _DictRedis()
    manager = _manager(redis)
    manager._owned_patterns = ["wp60pattern"]
    manager._persist_last_known_rules(_rules(rule_id="r", version=9))
    manager._owned_patterns = []
    held = manager._parse_if_holding(redis.store[LEGACY], redis.store[FULL], "r", 9)
    assert held is not None
    assert held[1] == ["wp60pattern"]
