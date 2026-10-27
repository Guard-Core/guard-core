import pytest
from redis.asyncio import Redis

from guard_core.handlers._redis_lean import (
    NO_COUNTER_REPLY,
    NOT_A_LIST_REPLY,
    lean_evalsha,
    reply_counts,
)


def _client_replying(monkeypatch: pytest.MonkeyPatch, reply: object) -> Redis:
    async def execute_command(*args: object, **options: object) -> object:
        return reply

    client = Redis()
    monkeypatch.setattr(client, "execute_command", execute_command)
    return client


async def test_evalsha_replying_with_a_list_returns_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client_replying(monkeypatch, [1, "a", None])
    assert await lean_evalsha(client, "return 1", "sha", ["k"], ["a"]) == [
        1,
        "a",
        None,
    ]


@pytest.mark.parametrize("reply", [None, 7, "OK", b"OK"])
async def test_evalsha_replying_with_anything_but_a_list_raises(
    monkeypatch: pytest.MonkeyPatch, reply: object
) -> None:
    client = _client_replying(monkeypatch, reply)
    with pytest.raises(TypeError, match=NOT_A_LIST_REPLY):
        await lean_evalsha(client, "return 1", "sha", ["k"], ["a"])


def test_reply_counts_reads_every_shape_a_counter_comes_back_in() -> None:
    assert reply_counts([3, "4", b"5", 6.0]) == [3, 4, 5, 6]


def test_reply_counts_refuses_a_missing_counter() -> None:
    with pytest.raises(TypeError, match=NO_COUNTER_REPLY):
        reply_counts([1, None])
