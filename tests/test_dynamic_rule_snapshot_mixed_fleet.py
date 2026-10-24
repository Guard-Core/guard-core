import json
import logging
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from guard_core._dynamic_rules import (
    dump_last_known_rules_snapshot,
    dump_legacy_last_known_rules_snapshot,
)
from guard_core.handlers._dynamic_rule_persistence import (
    DYNAMIC_RULES_REDIS_NAMESPACE,
    LAST_KNOWN_RULES_FULL_KEY,
    LAST_KNOWN_RULES_KEY,
)
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.models import DynamicRules, SecurityConfig

MANAGER_LOGGER = "guard_core.handlers.dynamic_rule"

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


class _DictRedis:
    def __init__(self) -> None:
        self.store: dict[tuple[str, str], str] = {}
        self.get_key = AsyncMock(side_effect=self._get)
        self.set_key = AsyncMock(side_effect=self._set)
        self.delete = AsyncMock(side_effect=self._delete)

    async def _get(self, namespace: str, key: str) -> str | None:
        return self.store.get((namespace, key))

    async def _set(self, namespace: str, key: str, value: str) -> bool:
        self.store[(namespace, key)] = value
        return True

    async def _delete(self, namespace: str, key: str) -> int:
        return int(self.store.pop((namespace, key), None) is not None)


LEGACY = (DYNAMIC_RULES_REDIS_NAMESPACE, LAST_KNOWN_RULES_KEY)
FULL = (DYNAMIC_RULES_REDIS_NAMESPACE, LAST_KNOWN_RULES_FULL_KEY)


@pytest.fixture(autouse=True)
def reset_singleton() -> Iterator[None]:
    DynamicRuleManager._instance = None
    yield
    DynamicRuleManager._instance = None


async def _manager(
    redis: _DictRedis | None, cache_path: Path | None = None
) -> DynamicRuleManager:
    manager = DynamicRuleManager(SecurityConfig(dynamic_rules_cache_path=cache_path))
    if redis is not None:
        await manager.initialize_redis(redis)
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


@pytest.mark.asyncio
async def test_persist_writes_the_legacy_key_and_the_full_key() -> None:
    redis = _DictRedis()
    manager = await _manager(redis)
    manager._owned_bans = ["203.0.113.7"]
    await manager._persist_last_known_rules(_rules(emergency_whitelist_only=False))
    legacy = json.loads(redis.store[LEGACY])
    full = json.loads(redis.store[FULL])
    assert set(legacy) == V440_SNAPSHOT_KEYS
    assert set(legacy["rules"]) == V440_RULE_FIELDS
    assert full["owned"]["bans"] == ["203.0.113.7"]
    assert full["rules"]["emergency_whitelist_only"] is False
    assert [call.args[1] for call in redis.set_key.call_args_list] == [
        LAST_KNOWN_RULES_KEY,
        LAST_KNOWN_RULES_FULL_KEY,
    ]


@pytest.mark.asyncio
async def test_persist_writes_the_legacy_file_and_the_full_file(
    tmp_path: Path,
) -> None:
    cache = tmp_path / "rules.json"
    manager = await _manager(None, cache)
    await manager._persist_last_known_rules(_rules(emergency_whitelist_only=False))
    assert set(json.loads(cache.read_text())["rules"]) == V440_RULE_FIELDS
    full = json.loads((tmp_path / "rules.json.full").read_text())
    assert full["rules"]["emergency_whitelist_only"] is False


@pytest.mark.asyncio
async def test_a_full_snapshot_that_agrees_is_used_whole() -> None:
    redis = _DictRedis()
    writer = await _manager(redis)
    writer._owned_bans = ["203.0.113.7"]
    await writer._persist_last_known_rules(_rules(emergency_whitelist_only=False))
    DynamicRuleManager._instance = None
    reader = await _manager(redis)
    rules = await reader._load_last_known_rules()
    assert rules is not None
    assert rules.emergency_whitelist_only is False
    assert reader._restored_ownership == (["203.0.113.7"], [])


@pytest.mark.asyncio
async def test_a_legacy_write_after_a_full_write_wins_with_one_log_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    redis = _DictRedis()
    writer = await _manager(redis)
    writer._owned_bans = ["203.0.113.7"]
    await writer._persist_last_known_rules(_rules(version=1))
    redis.store[LEGACY] = dump_legacy_last_known_rules_snapshot(_rules(version=2))
    DynamicRuleManager._instance = None
    reader = await _manager(redis)
    with caplog.at_level(logging.DEBUG, logger=MANAGER_LOGGER):
        rules = await reader._load_last_known_rules()
    assert rules is not None
    assert rules.version == 2
    assert reader._restored_ownership == ([], [])
    assert [r.levelname for r in caplog.records] == ["WARNING"]
    assert "differs from the legacy snapshot" in caplog.records[0].getMessage()


@pytest.mark.asyncio
async def test_an_unusable_full_snapshot_falls_back_to_legacy_with_one_log_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    redis = _DictRedis()
    redis.store[LEGACY] = dump_legacy_last_known_rules_snapshot(_rules(version=4))
    redis.store[FULL] = "{not json"
    reader = await _manager(redis)
    with caplog.at_level(logging.DEBUG, logger=MANAGER_LOGGER):
        rules = await reader._load_last_known_rules()
    assert rules is not None
    assert rules.version == 4
    assert [r.levelname for r in caplog.records] == ["WARNING"]
    assert "is unusable" in caplog.records[0].getMessage()


@pytest.mark.asyncio
async def test_a_full_snapshot_without_a_legacy_one_is_not_used() -> None:
    redis = _DictRedis()
    redis.store[FULL] = dump_last_known_rules_snapshot(_rules(), [], [])
    reader = await _manager(redis)
    assert await reader._load_last_known_rules() is None


@pytest.mark.asyncio
async def test_clear_removes_both_keys_and_both_files(tmp_path: Path) -> None:
    redis = _DictRedis()
    cache = tmp_path / "rules.json"
    manager = await _manager(redis, cache)
    await manager._persist_last_known_rules(_rules())
    await manager._clear_last_known_rules()
    assert redis.store == {}
    assert list(tmp_path.iterdir()) == []


@pytest.mark.asyncio
async def test_purge_takes_the_owned_patterns_from_the_full_snapshot() -> None:
    redis = _DictRedis()
    manager = await _manager(redis)
    manager._owned_patterns = ["wp60pattern"]
    await manager._persist_last_known_rules(_rules(rule_id="r", version=9))
    manager._owned_patterns = []
    held = manager._parse_if_holding(redis.store[LEGACY], redis.store[FULL], "r", 9)
    assert held is not None
    assert held[1] == ["wp60pattern"]
