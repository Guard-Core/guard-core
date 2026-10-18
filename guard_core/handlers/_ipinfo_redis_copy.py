import logging
from pathlib import Path
from typing import Any

from maxminddb import Reader

from guard_core.protocols.redis_protocol import RedisHandlerProtocol


class IpInfoRedisCopyMixin:
    db_path: Path
    redis_handler: RedisHandlerProtocol | None
    logger: logging.Logger
    _DOWNLOAD_LOCK_SECONDS: int

    def _write_database_atomically(self, content: bytes) -> None: ...

    def _open_database_or_none(self) -> Reader | None: ...

    def _apply_opened_reader(self, reader: Reader | None) -> None: ...

    async def _adopt_redis_copy(self) -> bool:
        if not self.redis_handler:
            return False
        try:
            cached_db = await self.redis_handler.get_key("ipinfo", "database")
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
            await self._drop_cached_database(self.redis_handler)
            return False
        reader = self._open_database_or_none()
        if reader is None:
            await self._drop_cached_database(self.redis_handler)
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
        redis: Any = self.redis_handler
        if redis is None:
            return True
        try:
            claimed = await redis.set_key_if_absent(
                "ipinfo", "download_lock", "1", self._DOWNLOAD_LOCK_SECONDS
            )
        except Exception as e:
            self.logger.warning(
                "GeoIP download lock unavailable, downloading anyway: %s", e
            )
            return True
        return bool(claimed)
