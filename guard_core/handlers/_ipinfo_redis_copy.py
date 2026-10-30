from __future__ import annotations

import logging
import time
import uuid
import weakref
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from guard_core.handlers._ipinfo_redis_pieces import (
    DatabaseKeyChanged,
    read_pieces_into_file,
    store_file_in_pieces,
)
from guard_core.handlers._redis_handler_support import as_stored_value
from guard_core.protocols.redis_protocol import RedisHandlerProtocol

if TYPE_CHECKING:
    from maxminddb import Reader


class IpInfoRedisCopyMixin:
    db_path: Path
    redis_handler: RedisHandlerProtocol | None
    _bound_redis_refs: tuple[Callable[[], RedisHandlerProtocol | None], ...] = ()
    logger: logging.Logger
    _DOWNLOAD_LOCK_SECONDS: int
    _download_lock_token: str = ""
    _download_total_timeout: float
    _max_age: int

    def _write_database_atomically(self, content: bytes) -> None: ...

    def _database_tmp_path(self) -> Path:
        return self.db_path.with_name(f"{self.db_path.name}.{uuid.uuid4().hex}.tmp")

    def _remove_stale_temp_files(self) -> None:
        oldest = time.time() - self._download_total_timeout
        names = (f"{self.db_path.name}.tmp", f"{self.db_path.name}.*.tmp")
        for pattern in names:
            for leftover in self.db_path.parent.glob(pattern):
                try:
                    if leftover.stat().st_mtime < oldest:
                        leftover.unlink(missing_ok=True)
                except OSError:
                    continue

    def _install_database_file(self, tmp_path: Path) -> None: ...

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
            newest: Callable[[], RedisHandlerProtocol | None] = weakref.ref(
                redis_handler
            )
        except TypeError:

            def newest() -> RedisHandlerProtocol | None:
                return redis_handler

        self._bound_redis_refs = (*kept, newest)

    def _redis_key_prefix(self, redis_handler: RedisHandlerProtocol) -> str | None:
        config = getattr(redis_handler, "config", None)
        prefix = getattr(config, "redis_prefix", None)
        enabled = getattr(config, "enable_redis", False)
        return prefix if enabled is True and isinstance(prefix, str) else None

    async def _cache_database_in_redis(
        self,
        handlers: list[RedisHandlerProtocol] | None = None,
        only_if_absent: bool = False,
    ) -> None:
        targets = self._copy_handlers() if handlers is None else handlers
        for redis_handler in targets:
            try:
                await self._store_copy_in(redis_handler, only_if_absent)
            except Exception as e:
                self.logger.warning("Failed to cache GeoIP database in Redis: %s", e)

    async def _store_copy_in(
        self, redis_handler: RedisHandlerProtocol, only_if_absent: bool
    ) -> None:
        prefix = self._redis_key_prefix(redis_handler)
        if prefix is None:
            content = self.db_path.read_bytes().decode("latin-1")
            if only_if_absent:
                await redis_handler.set_key_if_absent(
                    "ipinfo", "database", content, self._max_age
                )
            else:
                await redis_handler.set_key(
                    "ipinfo", "database", content, ttl=self._max_age
                )
            return
        final_key = f"{prefix}ipinfo:database"
        async with redis_handler.get_connection() as conn:
            if only_if_absent and await conn.exists(final_key):
                return
            await store_file_in_pieces(
                conn,
                self.db_path,
                final_key,
                f"{final_key}:{uuid.uuid4().hex}",
                self._max_age,
                int(self._download_total_timeout),
            )

    async def _adopt_redis_copy(self) -> bool:
        for redis_handler in self._copy_handlers():
            if await self._adopt_copy_from(redis_handler):
                await self._cache_database_in_redis(
                    [h for h in self._copy_handlers() if h is not redis_handler],
                    only_if_absent=True,
                )
                return True
        return False

    async def _adopt_copy_from(self, redis_handler: RedisHandlerProtocol) -> bool:
        prefix = self._redis_key_prefix(redis_handler)
        if prefix is not None:
            return await self._adopt_redis_pieces(redis_handler, prefix)
        return await self._adopt_whole_redis_copy(redis_handler)

    async def _adopt_redis_pieces(
        self, redis_handler: RedisHandlerProtocol, prefix: str
    ) -> bool:
        target = self._database_tmp_path()
        try:
            async with redis_handler.get_connection() as conn:
                present = await read_pieces_into_file(
                    conn, f"{prefix}ipinfo:database", target
                )
        except DatabaseKeyChanged:
            target.unlink(missing_ok=True)
            self.logger.warning("Cached GeoIP database kept changing while read")
            return False
        except ValueError:
            target.unlink(missing_ok=True)
            await self._drop_cached_database(redis_handler)
            return False
        except Exception as e:
            target.unlink(missing_ok=True)
            self.logger.warning("Cached GeoIP database unavailable: %s", e)
            return False
        if not present:
            target.unlink(missing_ok=True)
            return False
        try:
            self._install_database_file(target)
        except ValueError:
            await self._drop_cached_database(redis_handler)
            return False
        except OSError as e:
            self.logger.warning("Cached GeoIP database could not be installed: %s", e)
            return False
        return await self._adopt_installed_database(redis_handler)

    async def _adopt_installed_database(
        self, redis_handler: RedisHandlerProtocol
    ) -> bool:
        reader = self._open_database_or_none()
        if reader is None:
            await self._drop_cached_database(redis_handler)
            return False
        self._apply_opened_reader(reader)
        return True

    async def _adopt_whole_redis_copy(
        self, redis_handler: RedisHandlerProtocol
    ) -> bool:
        try:
            cached_db = as_stored_value(
                await redis_handler.get_key("ipinfo", "database")
            )
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
        except OSError as e:
            self.logger.warning("Cached GeoIP database could not be installed: %s", e)
            return False
        return await self._adopt_installed_database(redis_handler)

    async def _drop_cached_database(self, redis_handler: RedisHandlerProtocol) -> None:
        self.logger.warning("Cached GeoIP database is unusable, downloading again")
        try:
            await redis_handler.delete("ipinfo", "database")
        except Exception as e:
            self.logger.warning("Cached GeoIP database could not be dropped: %s", e)

    async def _claim_download_lock(self) -> bool:
        self._download_lock_token = uuid.uuid4().hex
        claimed: list[RedisHandlerProtocol] = []
        for redis in self._copy_handlers():
            try:
                won = await redis.set_key_if_absent(
                    "ipinfo",
                    "download_lock",
                    self._download_lock_token,
                    self._DOWNLOAD_LOCK_SECONDS,
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

    async def _release_download_lock(
        self, handlers: list[RedisHandlerProtocol]
    ) -> None:
        for redis in handlers:
            try:
                # only the lock this worker took: an expired one may be another's
                if await redis.get_key("ipinfo", "download_lock") == (
                    self._download_lock_token
                ):
                    await redis.delete("ipinfo", "download_lock")
            except Exception as e:
                self.logger.warning("GeoIP download lock not released: %s", e)
