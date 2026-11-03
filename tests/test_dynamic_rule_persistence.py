import json
import logging
from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from guard_agent.models import DynamicRules as AgentDynamicRules

from guard_core._dynamic_rules import (
    LAST_KNOWN_RULES_SNAPSHOT_SCHEMA_VERSION,
    dump_last_known_rules_snapshot,
    dump_legacy_last_known_rules_snapshot,
    load_last_known_rules_snapshot,
)
from guard_core.handlers._dynamic_rule_persistence import (
    DYNAMIC_RULES_REDIS_NAMESPACE,
    LAST_KNOWN_RULES_FULL_KEY,
    LAST_KNOWN_RULES_KEY,
)
from guard_core.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import DynamicRules, SecurityConfig
from tests.conftest import REDIS_URL, suite_redis_prefix

MANAGER_LOGGER = "guard_core.handlers.dynamic_rule"


def _rules(**kwargs: object) -> DynamicRules:
    base = {
        "rule_id": "test-rule",
        "version": 1,
        "timestamp": datetime.now(timezone.utc),
    }
    base.update(kwargs)
    return DynamicRules(**base)


def _snapshot(rules: DynamicRules) -> str:
    return dump_last_known_rules_snapshot(rules, [], [])


def _legacy_snapshot(rules: DynamicRules) -> str:
    return dump_legacy_last_known_rules_snapshot(rules)


def _agent_rules(**kwargs: object) -> DynamicRules:
    base = {
        "rule_id": "agent-rule",
        "version": 3,
        "timestamp": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
        "emergency_whitelist_only": True,
        "message": "maintenance",
        "ip_blacklist": ["1.2.3.4"],
        "emergency_mode": False,
    }
    base.update(kwargs)
    return cast(DynamicRules, AgentDynamicRules(**base))


def _redis(payload: object) -> AsyncMock:
    redis = AsyncMock()
    redis.get_key = AsyncMock(return_value=payload)
    redis.set_key = AsyncMock(return_value=True)
    return redis


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    DynamicRuleManager._instance = None
    yield
    DynamicRuleManager._instance = None


@pytest.mark.asyncio
async def test_apply_rules_persists_last_known_rules_to_redis() -> None:
    config = SecurityConfig(auto_ban_threshold=5)
    manager = DynamicRuleManager(config)
    redis = _redis(None)
    await manager.initialize_redis(redis)

    rules = _rules(auto_ban_threshold=7)
    await manager._apply_rules(rules)

    assert [call.args for call in redis.set_key.call_args_list] == [
        (DYNAMIC_RULES_REDIS_NAMESPACE, LAST_KNOWN_RULES_KEY, _legacy_snapshot(rules)),
        (DYNAMIC_RULES_REDIS_NAMESPACE, LAST_KNOWN_RULES_FULL_KEY, _snapshot(rules)),
    ]
    assert config.auto_ban_threshold == 7


@pytest.mark.asyncio
async def test_apply_rules_persists_last_known_rules_to_file(tmp_path: Path) -> None:
    cache_path = tmp_path / "dynamic_rules.json"
    config = SecurityConfig(
        auto_ban_threshold=5, dynamic_rules_cache_path=str(cache_path)
    )
    manager = DynamicRuleManager(config)

    rules = _rules(auto_ban_threshold=7)
    await manager._apply_rules(rules)

    assert cache_path.read_text(encoding="utf-8") == _legacy_snapshot(rules)
    full_path = tmp_path / "dynamic_rules.json.full"
    assert full_path.read_text(encoding="utf-8") == _snapshot(rules)


@pytest.mark.asyncio
async def test_apply_rules_persists_to_both_redis_and_file(tmp_path: Path) -> None:
    cache_path = tmp_path / "dynamic_rules.json"
    config = SecurityConfig(auto_ban_threshold=5, dynamic_rules_cache_path=cache_path)
    manager = DynamicRuleManager(config)
    redis = _redis(None)
    await manager.initialize_redis(redis)

    rules = _rules(auto_ban_threshold=7)
    await manager._apply_rules(rules)

    assert redis.set_key.await_count == 2
    assert cache_path.read_text(encoding="utf-8") == _legacy_snapshot(rules)


@pytest.mark.asyncio
async def test_apply_rules_survives_redis_write_failure() -> None:
    config = SecurityConfig(auto_ban_threshold=5)
    manager = DynamicRuleManager(config)
    redis = _redis(None)
    redis.set_key = AsyncMock(side_effect=RuntimeError("redis down"))
    await manager.initialize_redis(redis)

    await manager._apply_rules(_rules(auto_ban_threshold=7))

    assert config.auto_ban_threshold == 7


@pytest.mark.asyncio
async def test_apply_rules_survives_cache_file_write_failure(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    cache_path = tmp_path / "missing-dir" / "dynamic_rules.json"
    config = SecurityConfig(
        auto_ban_threshold=5, dynamic_rules_cache_path=str(cache_path)
    )
    manager = DynamicRuleManager(config)

    with caplog.at_level(logging.ERROR, logger=MANAGER_LOGGER):
        await manager._apply_rules(_rules(auto_ban_threshold=7))

    assert config.auto_ban_threshold == 7
    assert "Failed to persist dynamic rules to cache file" in caplog.text


@pytest.mark.asyncio
async def test_restart_with_saas_down_hydrates_last_known_rules_from_redis() -> None:
    config = SecurityConfig(
        enable_dynamic_rules=True,
        enable_agent=True,
        agent_api_key="key",
        auto_ban_threshold=5,
    )
    manager = DynamicRuleManager(config)
    rules = _rules(auto_ban_threshold=7)
    await manager.initialize_redis(_redis(_snapshot(rules)))

    with patch.object(DynamicRuleManager, "_rule_update_loop", new_callable=AsyncMock):
        await manager.initialize_agent(AsyncMock())

    assert config.auto_ban_threshold == 7
    assert manager.current_rules == rules
    assert manager._active_base_snapshot is not None
    assert manager._active_base_snapshot["auto_ban_threshold"] == 5
    await manager.stop()


@pytest.mark.asyncio
async def test_restart_hydrates_from_real_redis_snapshot() -> None:
    prefix = suite_redis_prefix("guard-core-dynamic-rules")
    store_config = SecurityConfig(
        enable_redis=True, redis_url=REDIS_URL, redis_prefix=prefix
    )
    store = RedisManager(store_config)
    await store.initialize()
    rules = _rules(auto_ban_threshold=7)
    try:
        await store.set_key(
            DYNAMIC_RULES_REDIS_NAMESPACE, LAST_KNOWN_RULES_KEY, _snapshot(rules)
        )
    except Exception:
        await store.close()
        pytest.fail("Redis is not reachable; the restart hydration test needs it")

    restart_config = SecurityConfig(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=prefix,
        enable_dynamic_rules=True,
        enable_agent=True,
        agent_api_key="key",
        auto_ban_threshold=5,
    )
    try:
        restarted = DynamicRuleManager(restart_config)
        await restarted.initialize_redis(store)
        with patch.object(
            DynamicRuleManager, "_rule_update_loop", new_callable=AsyncMock
        ):
            await restarted.initialize_agent(MagicMock())

        assert restart_config.auto_ban_threshold == 7
        assert restarted.current_rules == rules
        assert restarted._active_base_snapshot is not None
        assert restarted._active_base_snapshot["auto_ban_threshold"] == 5
    finally:
        await store.delete(DYNAMIC_RULES_REDIS_NAMESPACE, LAST_KNOWN_RULES_KEY)
        await store.close()
        DynamicRuleManager._instance = None


@pytest.mark.asyncio
async def test_hydration_falls_back_to_file_when_redis_empty(tmp_path: Path) -> None:
    cache_path = tmp_path / "dynamic_rules.json"
    rules = _rules(auto_ban_threshold=9)
    cache_path.write_text(_snapshot(rules), encoding="utf-8")

    config = SecurityConfig(
        auto_ban_threshold=5, dynamic_rules_cache_path=str(cache_path)
    )
    manager = DynamicRuleManager(config)
    await manager.initialize_redis(_redis(None))

    await manager._hydrate_last_known_rules()

    assert config.auto_ban_threshold == 9
    assert manager.current_rules == rules


@pytest.mark.asyncio
async def test_hydration_decodes_bytes_redis_payload() -> None:
    rules = _rules(auto_ban_threshold=9)
    config = SecurityConfig(auto_ban_threshold=5)
    manager = DynamicRuleManager(config)
    await manager.initialize_redis(_redis(_snapshot(rules).encode("utf-8")))

    await manager._hydrate_last_known_rules()

    assert config.auto_ban_threshold == 9
    assert manager.current_rules == rules


@pytest.mark.asyncio
async def test_hydration_prefers_redis_snapshot_over_file(tmp_path: Path) -> None:
    redis_rules = _rules(rule_id="redis-rule", version=2, auto_ban_threshold=8)
    file_rules = _rules(rule_id="file-rule", version=1, auto_ban_threshold=6)
    cache_path = tmp_path / "dynamic_rules.json"
    cache_path.write_text(_snapshot(file_rules), encoding="utf-8")

    config = SecurityConfig(
        auto_ban_threshold=5, dynamic_rules_cache_path=str(cache_path)
    )
    manager = DynamicRuleManager(config)
    await manager.initialize_redis(_redis(_snapshot(redis_rules)))

    await manager._hydrate_last_known_rules()

    assert config.auto_ban_threshold == 8
    assert manager.current_rules == redis_rules


@pytest.mark.asyncio
async def test_hydration_falls_back_to_file_when_redis_payload_malformed(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    cache_path = tmp_path / "dynamic_rules.json"
    rules = _rules(rule_id="file-rule", auto_ban_threshold=9)
    cache_path.write_text(_snapshot(rules), encoding="utf-8")

    config = SecurityConfig(
        auto_ban_threshold=5, dynamic_rules_cache_path=str(cache_path)
    )
    manager = DynamicRuleManager(config)
    await manager.initialize_redis(_redis("{not json"))

    with caplog.at_level(logging.ERROR, logger=MANAGER_LOGGER):
        await manager._hydrate_last_known_rules()

    assert config.auto_ban_threshold == 9
    assert "Discarding unusable last-known dynamic rules payload" in caplog.text


@pytest.mark.asyncio
async def test_hydration_with_unusable_snapshots_stays_on_base_config(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    cache_path = tmp_path / "dynamic_rules.json"
    cache_path.write_text("definitely not json", encoding="utf-8")

    config = SecurityConfig(
        auto_ban_threshold=5, dynamic_rules_cache_path=str(cache_path)
    )
    manager = DynamicRuleManager(config)
    await manager.initialize_redis(_redis('{"schema": "unknown"}'))

    with caplog.at_level(logging.ERROR, logger=MANAGER_LOGGER):
        await manager._hydrate_last_known_rules()

    assert config.auto_ban_threshold == 5
    assert manager.current_rules is None
    assert manager._active_base_snapshot is None
    assert "Discarding unusable last-known dynamic rules payload" in caplog.text


@pytest.mark.asyncio
async def test_hydration_discards_expired_snapshot(
    caplog: pytest.LogCaptureFixture,
) -> None:
    expired = _rules(
        auto_ban_threshold=9,
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    config = SecurityConfig(auto_ban_threshold=5)
    manager = DynamicRuleManager(config)
    await manager.initialize_redis(_redis(_snapshot(expired)))

    with caplog.at_level(logging.ERROR, logger=MANAGER_LOGGER):
        await manager._hydrate_last_known_rules()

    assert config.auto_ban_threshold == 5
    assert manager.current_rules is None
    assert "Discarding expired last-known dynamic rules" in caplog.text


@pytest.mark.asyncio
async def test_hydration_discards_corrupt_cache_file(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    cache_path = tmp_path / "dynamic_rules.json"
    cache_path.write_bytes(b"\xff\xfe not utf-8 json")
    config = SecurityConfig(
        auto_ban_threshold=5, dynamic_rules_cache_path=str(cache_path)
    )
    manager = DynamicRuleManager(config)

    with caplog.at_level(logging.ERROR, logger=MANAGER_LOGGER):
        await manager._hydrate_last_known_rules()

    assert config.auto_ban_threshold == 5
    assert manager.current_rules is None
    assert "Failed to read dynamic rules cache file" in caplog.text


@pytest.mark.asyncio
async def test_hydration_accepts_sync_redis_handler_returning_plain_values() -> None:
    rules = _rules(auto_ban_threshold=9)
    config = SecurityConfig(auto_ban_threshold=5)
    manager = DynamicRuleManager(config)
    redis = MagicMock()
    redis.get_key = MagicMock(return_value=_snapshot(rules))
    redis.set_key = MagicMock(return_value=True)
    await manager.initialize_redis(redis)

    await manager._hydrate_last_known_rules()

    assert redis.set_key.call_count == 2
    assert config.auto_ban_threshold == 9
    assert manager.current_rules == rules


@pytest.mark.asyncio
async def test_hydration_survives_redis_read_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(auto_ban_threshold=5)
    manager = DynamicRuleManager(config)
    redis = _redis(None)
    redis.get_key = AsyncMock(side_effect=RuntimeError("connection refused"))
    await manager.initialize_redis(redis)

    with caplog.at_level(logging.ERROR, logger=MANAGER_LOGGER):
        await manager._hydrate_last_known_rules()

    assert config.auto_ban_threshold == 5
    assert manager.current_rules is None
    assert "Failed to read last-known dynamic rules from Redis" in caplog.text


@pytest.mark.asyncio
async def test_hydration_survives_failed_apply() -> None:
    config = SecurityConfig(auto_ban_threshold=5)
    manager = DynamicRuleManager(config)
    await manager.initialize_redis(_redis(_snapshot(_rules(auto_ban_threshold=9))))

    with patch.object(
        manager, "_apply_rules", AsyncMock(side_effect=RuntimeError("kaboom"))
    ):
        await manager._hydrate_last_known_rules()

    assert config.auto_ban_threshold == 5
    assert manager.current_rules is None


@pytest.mark.asyncio
async def test_initialize_agent_without_stored_snapshot_keeps_base_config() -> None:
    config = SecurityConfig(
        enable_dynamic_rules=True,
        enable_agent=True,
        agent_api_key="key",
        auto_ban_threshold=5,
    )
    manager = DynamicRuleManager(config)

    with patch.object(DynamicRuleManager, "_rule_update_loop", new_callable=AsyncMock):
        await manager.initialize_agent(MagicMock())

    assert config.auto_ban_threshold == 5
    assert manager.current_rules is None
    await manager.stop()


@pytest.mark.asyncio
async def test_initialize_agent_skips_hydration_when_dynamic_rules_disabled() -> None:
    config = SecurityConfig(auto_ban_threshold=5)
    manager = DynamicRuleManager(config)

    with patch.object(
        manager, "_hydrate_last_known_rules", new_callable=AsyncMock
    ) as hydrate_mock:
        await manager.initialize_agent(MagicMock())

    hydrate_mock.assert_not_awaited()


@pytest.mark.asyncio
async def test_first_successful_fetch_supersedes_hydrated_state() -> None:
    config = SecurityConfig(
        enable_dynamic_rules=True,
        enable_agent=True,
        agent_api_key="key",
        auto_ban_threshold=5,
    )
    manager = DynamicRuleManager(config)
    hydrated = _rules(rule_id="hydrated-rule", version=1, auto_ban_threshold=7)
    await manager.initialize_redis(_redis(_snapshot(hydrated)))
    await manager._hydrate_last_known_rules()
    assert config.auto_ban_threshold == 7

    newer = _rules(rule_id="hydrated-rule", version=4, auto_ban_threshold=11)
    manager.agent_handler = MagicMock()
    manager.agent_handler.get_dynamic_rules = AsyncMock(return_value=newer)
    manager.agent_handler.send_event = AsyncMock()

    await manager.update_rules()

    assert manager.current_rules == newer
    assert config.auto_ban_threshold == 11


@pytest.mark.asyncio
async def test_hydrated_state_replaced_when_fetch_returns_a_rollback() -> None:
    config = SecurityConfig(
        enable_dynamic_rules=True,
        enable_agent=True,
        agent_api_key="key",
        auto_ban_threshold=5,
    )
    manager = DynamicRuleManager(config)
    hydrated = _rules(rule_id="hydrated-rule", version=3, auto_ban_threshold=7)
    await manager.initialize_redis(_redis(_snapshot(hydrated)))
    await manager._hydrate_last_known_rules()
    assert config.auto_ban_threshold == 7

    older = _rules(rule_id="hydrated-rule", version=2, auto_ban_threshold=9)
    manager.agent_handler = MagicMock()
    manager.agent_handler.get_dynamic_rules = AsyncMock(return_value=older)
    manager.agent_handler.send_event = AsyncMock()

    await manager.update_rules()

    assert manager.current_rules == older
    assert config.auto_ban_threshold == 9


@pytest.mark.asyncio
async def test_hydration_falls_back_to_file_when_redis_snapshot_expired(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    expired = _rules(
        rule_id="expired-rule",
        version=2,
        auto_ban_threshold=8,
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    file_rules = _rules(rule_id="file-rule", version=1, auto_ban_threshold=6)
    cache_path = tmp_path / "dynamic_rules.json"
    cache_path.write_text(_snapshot(file_rules), encoding="utf-8")

    config = SecurityConfig(
        auto_ban_threshold=5, dynamic_rules_cache_path=str(cache_path)
    )
    manager = DynamicRuleManager(config)
    await manager.initialize_redis(_redis(_snapshot(expired)))

    with caplog.at_level(logging.ERROR, logger=MANAGER_LOGGER):
        await manager._hydrate_last_known_rules()

    assert config.auto_ban_threshold == 6
    assert manager.current_rules == file_rules
    assert "Discarding expired last-known dynamic rules" in caplog.text


def _envelope_with_extra_rule_field(rules: DynamicRules, field: str) -> str:
    envelope = json.loads(dump_last_known_rules_snapshot(rules))
    envelope["rules"][field] = "future"
    return json.dumps(envelope)


@pytest.mark.asyncio
async def test_hydration_discards_snapshot_with_unknown_rule_fields(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    rules = _rules(auto_ban_threshold=9)
    config = SecurityConfig(
        auto_ban_threshold=5,
        dynamic_rules_cache_path=str(tmp_path / "dynamic_rules.json"),
    )
    manager = DynamicRuleManager(config)
    redis = _redis(_envelope_with_extra_rule_field(rules, "future_field"))
    await manager.initialize_redis(redis)

    with caplog.at_level(logging.ERROR, logger=MANAGER_LOGGER):
        await manager._hydrate_last_known_rules()

    assert config.auto_ban_threshold == 5
    assert manager.current_rules is None
    assert "Discarding unusable last-known dynamic rules payload" in caplog.text
    redis.set_key.assert_not_awaited()


@pytest.mark.asyncio
async def test_hydration_discards_unknown_snapshot_schema_version(
    caplog: pytest.LogCaptureFixture,
) -> None:
    envelope = json.loads(_snapshot(_rules(auto_ban_threshold=9)))
    envelope["schema_version"] = LAST_KNOWN_RULES_SNAPSHOT_SCHEMA_VERSION + 1
    config = SecurityConfig(auto_ban_threshold=5)
    manager = DynamicRuleManager(config)
    redis = _redis(json.dumps(envelope))
    await manager.initialize_redis(redis)

    with caplog.at_level(logging.ERROR, logger=MANAGER_LOGGER):
        await manager._hydrate_last_known_rules()

    assert config.auto_ban_threshold == 5
    assert manager.current_rules is None
    assert "Unsupported last-known dynamic rules snapshot schema version" in caplog.text
    redis.set_key.assert_not_awaited()


@pytest.mark.asyncio
async def test_hydration_discards_legacy_bare_payload(
    caplog: pytest.LogCaptureFixture,
) -> None:
    rules = _rules(auto_ban_threshold=9)
    config = SecurityConfig(auto_ban_threshold=5)
    manager = DynamicRuleManager(config)
    await manager.initialize_redis(_redis(rules.model_dump_json()))

    with caplog.at_level(logging.ERROR, logger=MANAGER_LOGGER):
        await manager._hydrate_last_known_rules()

    assert config.auto_ban_threshold == 5
    assert manager.current_rules is None
    assert "Discarding unusable last-known dynamic rules payload" in caplog.text


@pytest.mark.asyncio
async def test_cache_file_replace_failure_preserves_previous_snapshot(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    cache_path = tmp_path / "dynamic_rules.json"
    previous = _snapshot(_rules(rule_id="previous", version=1, auto_ban_threshold=5))
    cache_path.write_text(previous, encoding="utf-8")

    config = SecurityConfig(
        auto_ban_threshold=5, dynamic_rules_cache_path=str(cache_path)
    )
    manager = DynamicRuleManager(config)

    with (
        caplog.at_level(logging.ERROR, logger=MANAGER_LOGGER),
        patch(
            "guard_core.handlers._dynamic_rule_snapshot.os.replace",
            side_effect=OSError("disk full"),
        ),
    ):
        await manager._apply_rules(_rules(rule_id="next", auto_ban_threshold=7))

    assert config.auto_ban_threshold == 7
    assert cache_path.read_text(encoding="utf-8") == previous
    assert list(tmp_path.glob("*.tmp")) == []
    assert "Failed to persist dynamic rules to cache file" in caplog.text


@pytest.mark.asyncio
async def test_second_initialize_agent_does_not_reapply_hydrated_rules(
    tmp_path: Path,
) -> None:
    cache_path = tmp_path / "dynamic_rules.json"
    config = SecurityConfig(
        enable_dynamic_rules=True,
        enable_agent=True,
        agent_api_key="key",
        auto_ban_threshold=5,
        dynamic_rules_cache_path=str(cache_path),
    )
    manager = DynamicRuleManager(config)
    rules = _rules(auto_ban_threshold=7)
    await manager.initialize_redis(_redis(_snapshot(rules)))

    with patch.object(DynamicRuleManager, "_rule_update_loop", new_callable=AsyncMock):
        await manager.initialize_agent(AsyncMock())
        assert config.auto_ban_threshold == 7

        with (
            patch.object(manager, "_apply_rules", new_callable=AsyncMock) as apply_mock,
            patch.object(
                manager, "_hydrate_last_known_rules", new_callable=AsyncMock
            ) as hydrate_mock,
        ):
            await manager.initialize_agent(AsyncMock())

    hydrate_mock.assert_not_awaited()
    apply_mock.assert_not_awaited()
    assert cache_path.read_text(encoding="utf-8") == _legacy_snapshot(rules)
    await manager.stop()


@pytest.mark.asyncio
async def test_hydrate_expiry_does_not_suppress_update_loop_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    expired = _rules(
        rule_id="expired-rule",
        version=2,
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    config = SecurityConfig(
        enable_dynamic_rules=True,
        enable_agent=True,
        agent_api_key="key",
    )
    manager = DynamicRuleManager(config)
    await manager.initialize_redis(_redis(_snapshot(expired)))
    await manager._hydrate_last_known_rules()

    manager.agent_handler = MagicMock()
    manager.agent_handler.get_dynamic_rules = AsyncMock(return_value=expired)
    manager.agent_handler.send_event = AsyncMock()

    with caplog.at_level(logging.WARNING, logger=MANAGER_LOGGER):
        await manager.update_rules()

    warnings = [
        r
        for r in caplog.records
        if r.levelname == "WARNING" and "already expired on receipt" in r.getMessage()
    ]
    assert len(warnings) == 1
    assert manager.current_rules is None


def test_guard_core_dynamic_rules_mirror_is_a_subset_of_guard_agent_model() -> None:
    assert set(DynamicRules.model_fields) <= set(AgentDynamicRules.model_fields)


def test_dump_last_known_rules_snapshot_excludes_guard_agent_only_fields() -> None:
    agent_rules = _agent_rules(emergency_whitelist_only=False)

    payload = dump_last_known_rules_snapshot(agent_rules)
    envelope = json.loads(payload)

    assert "message" not in envelope["rules"]
    assert envelope["rules"]["emergency_whitelist_only"] is False

    loaded = load_last_known_rules_snapshot(payload)
    assert loaded.rule_id == "agent-rule"
    assert loaded.version == 3
    assert loaded.ip_blacklist == ["1.2.3.4"]
    assert loaded.emergency_mode is False
    assert loaded.emergency_whitelist_only is False


@pytest.mark.asyncio
async def test_apply_rules_persists_snapshot_built_from_real_guard_agent_rules(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    cache_path = tmp_path / "dynamic_rules.json"
    config = SecurityConfig(
        auto_ban_threshold=5, dynamic_rules_cache_path=str(cache_path)
    )
    manager = DynamicRuleManager(config)
    agent_rules = _agent_rules()

    with caplog.at_level(logging.ERROR, logger=MANAGER_LOGGER):
        await manager._apply_rules(agent_rules)

    assert cache_path.is_file()
    loaded = load_last_known_rules_snapshot(cache_path.read_text(encoding="utf-8"))
    assert loaded.rule_id == "agent-rule"
    assert loaded.version == 3
    assert loaded.ip_blacklist == ["1.2.3.4"]
    assert loaded.emergency_mode is False
    assert not [r for r in caplog.records if r.levelname == "ERROR"]


@pytest.mark.asyncio
async def test_apply_rules_persists_snapshot_built_from_real_guard_agent_rules_to_redis(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(auto_ban_threshold=5)
    manager = DynamicRuleManager(config)
    redis = _redis(None)
    await manager.initialize_redis(redis)
    agent_rules = _agent_rules()

    with caplog.at_level(logging.ERROR, logger=MANAGER_LOGGER):
        await manager._apply_rules(agent_rules)

    assert redis.set_key.await_count == 2
    payload = redis.set_key.call_args_list[0].args[2]
    loaded = load_last_known_rules_snapshot(payload)
    assert loaded.rule_id == "agent-rule"
    assert loaded.version == 3
    assert loaded.ip_blacklist == ["1.2.3.4"]
    assert loaded.emergency_mode is False
    assert not [r for r in caplog.records if r.levelname == "ERROR"]


@pytest.mark.asyncio
async def test_apply_rules_survives_snapshot_build_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(
        enable_dynamic_rules=True,
        enable_agent=True,
        agent_api_key="key",
        auto_ban_threshold=5,
    )
    manager = DynamicRuleManager(config)
    rules = _rules(auto_ban_threshold=7)
    manager.agent_handler = MagicMock()
    manager.agent_handler.get_dynamic_rules = AsyncMock(return_value=rules)
    manager.agent_handler.send_event = AsyncMock()

    with (
        caplog.at_level(logging.ERROR, logger=MANAGER_LOGGER),
        patch(
            "guard_core.handlers._dynamic_rule_snapshot.dump_last_known_rules_snapshot",
            side_effect=RuntimeError("boom"),
        ),
    ):
        await manager.update_rules()

    assert config.auto_ban_threshold == 7
    assert manager.current_rules == rules
    error_messages = [r.getMessage() for r in caplog.records if r.levelname == "ERROR"]
    assert (
        sum(
            "Failed to build last-known dynamic rules snapshot" in m
            for m in error_messages
        )
        == 1
    )
    assert not any("Failed to update dynamic rules" in m for m in error_messages)
