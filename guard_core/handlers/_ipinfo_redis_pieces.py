import codecs
from pathlib import Path
from typing import Any

from redis.client import NEVER_DECODE
from redis.exceptions import WatchError

PIECE_BYTES = 1048576
WATCH_RETRIES = 3


class DatabaseKeyChanged(Exception):
    pass


async def store_file_in_pieces(
    conn: Any, path: Path, final_key: str, temp_key: str, ttl: int, temp_ttl: int
) -> None:
    try:
        with open(path, "rb") as source:
            while piece := source.read(PIECE_BYTES):
                encoded = piece.decode("latin-1").encode("utf-8")
                if await conn.append(temp_key, encoded) == len(encoded):
                    await conn.expire(temp_key, temp_ttl)
        async with conn.pipeline(transaction=True) as swap:
            swap.rename(temp_key, final_key)
            swap.expire(final_key, ttl)
            await swap.execute()
    except BaseException:
        await conn.delete(temp_key)
        raise


async def read_pieces_into_file(conn: Any, key: str, target: Path) -> bool:
    for _ in range(WATCH_RETRIES):
        try:
            return await _read_watched(conn, key, target)
        except DatabaseKeyChanged:
            continue
    raise DatabaseKeyChanged(key)


async def _read_watched(conn: Any, key: str, target: Path) -> bool:
    async with conn.pipeline(transaction=True) as watched:
        await watched.watch(key)
        size = await watched.strlen(key)
        decoder = codecs.getincrementaldecoder("utf-8")()
        unreadable: ValueError | None = None
        with open(target, "wb") as sink:
            try:
                for offset in range(0, size, PIECE_BYTES):
                    raw = await watched.execute_command(
                        "GETRANGE",
                        key,
                        offset,
                        offset + PIECE_BYTES - 1,
                        **{NEVER_DECODE: []},
                    )
                    sink.write(decoder.decode(raw).encode("latin-1"))
                decoder.decode(b"", final=True)
            except ValueError as error:
                unreadable = error
        watched.multi()
        try:
            await watched.execute()
        except WatchError as changed:
            raise DatabaseKeyChanged(key) from changed
    if unreadable is not None:
        raise unreadable
    return bool(size > 0)
