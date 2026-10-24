from __future__ import annotations

import logging
import weakref
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from guard_core.protocols.redis_protocol import RedisHandlerProtocol

if TYPE_CHECKING:
    from maxminddb import Reader


class IpInfoRedisCopyMixin:
    db_path: Path
    redis_handler: RedisHandlerProtocol | None
    _bound_redis_refs: tuple[Callable[[], Any], ...] = ()
    logger: logging.Logger
    _DOWNLOAD_LOCK_SECONDS: int
    _max_age: int

    def _write_database_atomically(self, content: bytes) -> None: ...

    def _open_database_or_none(self) -> Reader | None: ...

    def _apply_opened_reader(self, reader: Reader | None) -> None: ...

    def _copy_handlers(self) -> list[RedisHandlerProtocol]:
        """The Redis handler of every app that shares this database, the most
        recent first. Each app keeps its copy under its own prefix."""
        live = [ref() for ref in reversed(self._bound_redis_refs)]
        ordered = [self.redis_handler, *live]
        return list({id(h): h for h in ordered if h is not None}.values())

    def _bind_redis_handler(self, redis_handler: RedisHandlerProtocol) -> None:
        self.redis_handler = redis_handler
        kept = tuple(
            ref
            for ref in self._bound_redis_refs
            if ref() is not None and ref() is not redis_handler
        )
        try:
            newest: Callable[[], Any] = weakref.ref(redis_handler)
        except TypeError:

            def newest() -> Any:
                return redis_handler

        self._bound_redis_refs = (*kept, newest)

    async def _adopt_redis_copy(self) -> bool:
        for redis_handler in self._copy_handlers():
            if await self._adopt_copy_from(redis_handler):
                await self._cache_database_in_redis(
                    [h for h in self._copy_handlers() if h is not redis_handler],
                    only_if_absent=True,
                )
                return True
        return False

    async def _cache_database_in_redis(
        self,
        handlers: list[RedisHandlerProtocol] | None = None,
        only_if_absent: bool = False,
    ) -> None:
        targets = self._copy_handlers() if handlers is None else handlers
        for redis_handler in targets:
            try:
                content = self.db_path.read_bytes().decode("latin-1")
                if only_if_absent:
                    await redis_handler.set_key_if_absent(
                        "ipinfo", "database", content, self._max_age
                    )
                else:
                    await redis_handler.set_key(
                        "ipinfo", "database", content, ttl=self._max_age
                    )
            except Exception as e:
                self.logger.warning("Failed to cache GeoIP database in Redis: %s", e)

    async def _adopt_copy_from(self, redis_handler: RedisHandlerProtocol) -> bool:
        try:
            cached_db = await redis_handler.get_key("ipinfo", "database")
        except Exception as e:
            self.logger.warning("Cached GeoIP database unavailable: %s", e)
            return False
        if not cached_db:
            return False
        try:
            self._write_database_atomically(
                cached_db
                if isinstance(cached_db, bytes)
                else cached_db.encode("latin-1")
            )
        except ValueError:
            await self._drop_cached_database(redis_handler)
            return False
        reader = self._open_database_or_none()
        if reader is None:
            await self._drop_cached_database(redis_handler)
            return False
        self._apply_opened_reader(reader)
        return True

    async def _drop_cached_database(self, redis_handler: RedisHandlerProtocol) -> None:
        self.logger.warning("Cached GeoIP database is unusable, downloading again")
        try:
            await redis_handler.delete("ipinfo", "database")
        except Exception as e:
            self.logger.warning("Cached GeoIP database could not be dropped: %s", e)

    async def _claim_download_lock(self) -> bool:
        claimed: list[Any] = []
        for redis in self._copy_handlers():
            try:
                won = await redis.set_key_if_absent(
                    "ipinfo", "download_lock", "1", self._DOWNLOAD_LOCK_SECONDS
                )
            except Exception as e:
                self.logger.warning(
                    "GeoIP download lock unavailable, downloading anyway: %s", e
                )
                continue
            if not won:
                await self._release_download_lock(claimed)
                return False
            claimed.append(redis)
        return True

    async def _release_download_lock(self, handlers: list[Any]) -> None:
        for redis in handlers:
            try:
                await redis.delete("ipinfo", "download_lock")
            except Exception as e:
                self.logger.warning("GeoIP download lock not released: %s", e)
