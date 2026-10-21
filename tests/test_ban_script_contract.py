import re

import pytest

from guard_core.handlers._dynamic_rule_persistence import parse_purge_target
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from guard_core.scripts import ban_write_lua


def _indices(script: str, name: str) -> set[int]:
    return {int(i) for i in re.findall(rf"{name}\[(\d+)\]", script)}


def test_the_extend_only_script_reads_the_keys_and_arguments_sent() -> None:
    script = ban_write_lua.EXTEND_ONLY_BAN_WRITE_SCRIPT

    assert _indices(script, "KEYS") == {1, 2, 3, 4}
    assert _indices(script, "ARGV") == {1, 2, 3, 4}


def test_the_purge_script_reads_the_three_keys_the_caller_sends() -> None:
    assert _indices(ban_write_lua.PURGE_OWNED_BAN_SCRIPT, "KEYS") == {1, 2, 3}
    assert _indices(ban_write_lua.PURGE_OWNED_BAN_SCRIPT, "ARGV") == set()


@pytest.mark.parametrize(
    ("value", "expected"),
    [("rule:3", ("rule", 3)), ("a:b:c:12", ("a:b:c", 12)), ("x:0", ("x", 0))],
)
def test_the_purge_target_splits_at_the_last_colon(
    value: str, expected: tuple[str, int]
) -> None:
    assert parse_purge_target(value) == expected


@pytest.mark.parametrize("value", ["", "nocolon", ":3", "id:", "id:x", "id:-1"])
def test_a_malformed_purge_target_is_refused(value: str) -> None:
    with pytest.raises(ValueError, match="rule_id:version"):
        parse_purge_target(value)


async def test_the_redis_ban_helpers_are_inert_when_redis_is_off() -> None:
    manager = RedisManager(SecurityConfig(enable_redis=False))
    manager.config = SecurityConfig(enable_redis=False)

    kept = await manager.write_ban_extending_only(
        "banned_ips", "198.51.100.1", "123.5", 60, version=("ban_version", "counter")
    )
    await manager.disown_ban("banned_ips", "198.51.100.1")

    assert kept == 123.5
    assert await manager.owned_ban_members() == []
    assert await manager.owned_ban_state("banned_ips", "198.51.100.1") == (None, None)
