from typing import Any

import pytest
from redis.asyncio.connection import Connection

from guard_core.handlers._redis_lean import _pack

BIG = "x" * 7000


def _plain(connection: Connection, args: tuple[Any, ...]) -> bytes:
    return b"".join(connection.pack_command(*args))


@pytest.mark.parametrize(
    "args",
    [
        ("GET", "key"),
        ("EVALSHA", "a" * 40, "2", "k1", "k2", "1|2.5|abc", ""),
        ("MGET", "café", "中文", "emoji\U0001f600"),
        ("EVALSHA", b"sha", b"1", b"key", b"arg"),
        ("SET", "k", "with space and\r\nnewline"),
        ("EVALSHA", "sha", 2, "k1", "k2", 1.5, 7),
        ("CONFIG GET", "maxmemory"),
        ("SET", "big", BIG),
    ],
)
def test_the_packed_command_equals_the_one_redis_py_builds(
    args: tuple[Any, ...],
) -> None:
    connection = Connection()
    assert b"".join(_pack(connection, args)) == _plain(connection, args)


def test_the_packed_command_follows_the_encoding_of_the_connection() -> None:
    connection = Connection(encoding="latin-1")
    args = ("SET", "k", "café")
    assert b"".join(_pack(connection, args)) == _plain(connection, args)
