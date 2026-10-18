import logging
from pathlib import Path
from typing import Any

from maxminddb import Reader

from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol


class IpInfoRedisCopyMixin:
    db_path: Path
    redis_handler: SyncRedisHandlerProtocol | None
    logger: logging.Logger
    _DOWNLOAD_LOCK_SECONDS: int

    def _write_database_atomically(self, content: bytes) -> None: ...

    def _open_database_or_none(self) -> Reader | None: ...

    def _apply_opened_reader(self, reader: Reader | None) -> None: ...

    def _adopt_redis_copy(self) -> bool:
        if not self.redis_handler:
            return False
        try:
            cached_db = self.redis_handler.get_key("ipinfo", "database")
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
            self._drop_cached_database(self.redis_handler)
            return False
        reader = self._open_database_or_none()
        if reader is None:
            self._drop_cached_database(self.redis_handler)
            return False
        self._apply_opened_reader(reader)
        return True

    def _drop_cached_database(self, redis_handler: SyncRedisHandlerProtocol) -> None:
        self.logger.warning("Cached GeoIP database is unusable, downloading again")
        try:
            redis_handler.delete("ipinfo", "database")
        except Exception as e:
            self.logger.warning("Cached GeoIP database could not be dropped: %s", e)

    def _claim_download_lock(self) -> bool:
        redis: Any = self.redis_handler
        if redis is None:
            return True
        try:
            claimed = redis.set_key_if_absent(
                "ipinfo", "download_lock", "1", self._DOWNLOAD_LOCK_SECONDS
            )
        except Exception as e:
            self.logger.warning(
                "GeoIP download lock unavailable, downloading anyway: %s", e
            )
            return True
        return bool(claimed)
