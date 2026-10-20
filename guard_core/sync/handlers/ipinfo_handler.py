from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from guard_core.sync.core.events.event_types import (
    EVENT_GEO_LOOKUP_FAILED,
)
from guard_core.sync.handlers._downloader import require_downloader_installed
from guard_core.sync.handlers._ipinfo_background import IpInfoBackgroundMixin
from guard_core.sync.handlers._ipinfo_download import IpInfoDownloadMixin
from guard_core.sync.handlers._ipinfo_events import IpInfoEventsMixin
from guard_core.sync.handlers._ipinfo_redis_copy import IpInfoRedisCopyMixin
from guard_core.sync.protocols.agent_protocol import SyncAgentHandlerProtocol
from guard_core.sync.protocols.redis_protocol import SyncRedisHandlerProtocol

if TYPE_CHECKING:
    from maxminddb import Reader


def _describe_download_error(exc: BaseException) -> str:
    status = getattr(exc, "status", None)
    if status is None:
        response = getattr(exc, "response", None)
        status = getattr(response, "status_code", None)
    if isinstance(status, int):
        return f"{type(exc).__name__} (HTTP {status})"
    return type(exc).__name__


class IPInfoManager(
    IpInfoBackgroundMixin,
    IpInfoRedisCopyMixin,
    IpInfoEventsMixin,
    IpInfoDownloadMixin,
):
    _instance = None
    _by_path: dict[Path, IPInfoManager] = {}
    _download_retries: int = 3
    _download_url: str = "https://ipinfo.io/data/free/country_asn.mmdb"
    _download_connect_timeout: float = 30
    _download_read_timeout: float = 30
    _download_total_timeout: float = 300
    _download_max_bytes: int = 134217728
    token: str
    db_path: Path
    reader: Reader | None = None
    redis_handler: SyncRedisHandlerProtocol | None = None
    agent_handler: SyncAgentHandlerProtocol | None = None
    logger: logging.Logger
    _max_age: int
    last_refreshed: datetime | None = None
    _initialization_attempted: bool = False
    _RETRY_BACKOFF_SECONDS: float = 60.0
    _last_attempt_at: float | None = None
    _background_in_flight: bool = False
    _background_task: threading.Thread | None = None
    _refresh_due: bool = False
    _staleness_timer: threading.Timer | None = None
    _DOWNLOAD_LOCK_SECONDS = 60

    def __new__(
        cls: type[IPInfoManager],
        token: str,
        db_path: Path | None = None,
        max_age: int = 86400,
    ) -> IPInfoManager:
        if not token:
            raise ValueError("IPInfo token is required!")

        path = db_path or Path("data/ipinfo/country_asn.mmdb")
        if cls._instance is None:
            cls._by_path = {}
        key = path.resolve()
        manager = cls._by_path.get(key)
        if manager is None:
            manager = cls._fresh(token, path, max_age)
            cls._by_path[key] = manager
            if cls._instance is None:
                cls._instance = manager
        else:
            manager._max_age = min(manager._max_age, max_age)
        return manager

    @classmethod
    def _fresh(
        cls: type[IPInfoManager], token: str, db_path: Path, max_age: int
    ) -> IPInfoManager:
        instance = super().__new__(cls)
        instance.token = token
        instance.db_path = db_path
        instance.reader = None
        instance.redis_handler = None
        instance.agent_handler = None
        instance.logger = logging.getLogger("guard_core.sync.handlers.ipinfo")
        instance._max_age = max_age
        instance.last_refreshed = None
        instance._initialization_attempted = False
        instance._last_attempt_at = None
        instance._background_in_flight = False
        instance._background_task = None
        instance._refresh_due = False
        instance._staleness_timer = None
        return instance

    @property
    def is_initialized(self) -> bool:
        return self.reader is not None

    @property
    def entry_count(self) -> int:
        if self.reader is None:
            return 0
        return self.reader.metadata().node_count

    def get_status(self) -> dict[str, Any]:
        return {
            "ready": self.is_initialized,
            "last_refreshed": self.last_refreshed,
            "entries": self.entry_count,
        }

    def initialize_agent(self, agent_handler: SyncAgentHandlerProtocol) -> None:
        self.agent_handler = agent_handler

    def _open_database_or_none(self) -> Reader | None:
        import maxminddb

        try:
            return maxminddb.open_database(str(self.db_path))
        except Exception as e:
            self.logger.error(
                f"IPInfo database at {self.db_path} is corrupted, removing: {e}"
            )
            if self.db_path.exists():
                self.db_path.unlink()
            return None

    def _apply_opened_reader(self, reader: Reader | None) -> None:
        if reader is not None:
            self.reader = reader
            self.last_refreshed = datetime.now(timezone.utc)
            self._refresh_due = False
            self._arm_staleness_timer()

    def _validate_database_file(self, path: Path) -> None:
        import maxminddb

        try:
            reader = maxminddb.open_database(str(path))
            try:
                reader.get("192.0.2.1")
            finally:
                reader.close()
        except Exception as e:
            raise ValueError(f"not a usable GeoIP database: {e}") from e

    def _write_database_atomically(self, content: bytes) -> None:
        tmp_path = self.db_path.with_name(self.db_path.name + ".tmp")
        try:
            with open(tmp_path, "wb") as f:
                f.write(content)
            self._validate_database_file(tmp_path)
            os.replace(tmp_path, self.db_path)
        except Exception:
            if tmp_path.exists():
                tmp_path.unlink()
            raise

    def initialize(self) -> None:
        self._start_or_join_load(self._initialize_database).join()

    def _initialize_database(self) -> None:
        try:
            os.makedirs(self.db_path.parent, exist_ok=True)

            if self._adopt_redis_copy():
                return

            try:
                if not self.db_path.exists() or self._is_db_outdated():
                    self._download_database()
            except Exception as e:
                self.logger.error(
                    "IPInfo database download failed, keeping existing reader: "
                    f"{_describe_download_error(e)}"
                )
                if self.agent_handler:
                    self._send_geo_event(
                        event_type=EVENT_GEO_LOOKUP_FAILED,
                        ip_address="system",
                        action_taken="database_download_failed",
                        reason=(
                            "Failed to download IPInfo database: "
                            f"{_describe_download_error(e)}"
                        ),
                    )
                self._warn_country_rules_without_database()
                return

            if self.db_path.exists():
                self._apply_opened_reader(self._open_database_or_none())
            self._warn_country_rules_without_database()
        finally:
            self._initialization_attempted = True

    def _warn_country_rules_without_database(self) -> None:
        if self.reader is not None:
            return
        self.logger.warning(
            "No GeoIP database is loaded: whitelist_countries denies every "
            "request and blocked_countries allows every request until it loads. "
            "The load is retried every %d s.",
            int(self._RETRY_BACKOFF_SECONDS),
        )

    def _download_database(self) -> None:
        if not self._claim_download_lock():
            self.logger.info(
                "Another worker is downloading the GeoIP database, "
                "its copy is picked up from Redis on the next attempt"
            )
            return
        try:
            self._fetch_and_store_database()
        finally:
            self._release_download_lock(self._copy_handlers())

    def _fetch_and_store_database(self) -> None:
        headers = {"Authorization": f"Bearer {self.token}"}
        retries = self._download_retries
        backoff = 1

        require_downloader_installed("geo", "Downloading the GeoIP database")
        import requests

        for attempt in range(retries):
            try:
                with requests.Session() as session:
                    content = self._download_body(session, headers)
                self._write_database_atomically(content)

                self._cache_database_in_redis()
                return
            except Exception:
                if attempt == retries - 1:
                    raise
                self._sleep(backoff)
                backoff *= 2

    def _sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def _is_db_outdated(self) -> bool:
        if not self.db_path.exists():
            return True

        age = time.time() - self.db_path.stat().st_mtime
        return age > self._max_age

    def _warn_reader_unavailable(self, ip: str) -> None:
        if self._initialization_attempted:
            self.logger.warning(
                "Geo-IP reader unavailable after a failed initialization "
                "attempt; returning None for %s. Check the IPInfo token and "
                "network reachability, then call refresh() to retry.",
                ip,
            )
        else:
            self.logger.warning(
                "Geo-IP reader uninitialized; returning None for %s", ip
            )

    def get_country(self, ip: str) -> str | None:
        if not self.reader:
            self._warn_reader_unavailable(ip)
            return None

        if self._refresh_due:
            self.schedule_database_load()

        try:
            result = self.reader.get(ip)
            if not isinstance(result, dict):
                return None
            if "country_code" in result:
                country = result["country_code"]
            elif "country" in result:
                country = result["country"]
            else:
                return None
            return str(country) if country is not None else None
        except Exception as e:
            if self.agent_handler:
                self._send_geo_event(
                    event_type=EVENT_GEO_LOOKUP_FAILED,
                    ip_address=ip,
                    action_taken="lookup_failed",
                    reason=f"Geographic lookup failed: {type(e).__name__}",
                )
            return None

    def close(self) -> None:
        self._cancel_staleness_timer()
        if self.reader:
            self.reader.close()

    def refresh(self) -> None:
        self._start_or_join_load(self._refresh_database).join()

    def _refresh_database(self) -> None:
        try:
            if self._adopt_redis_copy():
                return
            self._download_database()
        except Exception as e:
            self.logger.error(f"IPInfo refresh failed: {_describe_download_error(e)}")
            return
        finally:
            self._initialization_attempted = True

        if not self.db_path.exists():
            return

        self._apply_opened_reader(self._open_database_or_none())

    def initialize_redis(self, redis_handler: SyncRedisHandlerProtocol) -> None:
        self._bind_redis_handler(redis_handler)
        self.initialize()
