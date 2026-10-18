import asyncio
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiohttp
import maxminddb
from maxminddb import Reader

from guard_core.core.events.event_types import (
    EVENT_COUNTRY_BLOCKED,
    EVENT_GEO_LOOKUP_FAILED,
)
from guard_core.protocols.agent_protocol import AgentHandlerProtocol
from guard_core.protocols.redis_protocol import RedisHandlerProtocol

_IPINFO_HANDLER_NAME = "ipinfo"


def _describe_download_error(exc: BaseException) -> str:
    status = getattr(exc, "status", None)
    if status is None:
        response = getattr(exc, "response", None)
        status = getattr(response, "status_code", None)
    if isinstance(status, int):
        return f"{type(exc).__name__} (HTTP {status})"
    return type(exc).__name__


class IPInfoManager:
    _instance = None
    _download_retries: int = 3
    token: str
    db_path: Path
    reader: Reader | None = None
    redis_handler: RedisHandlerProtocol | None = None
    agent_handler: AgentHandlerProtocol | None = None
    logger: logging.Logger
    _max_age: int
    last_refreshed: datetime | None = None
    _initialization_attempted: bool = False
    _RETRY_BACKOFF_SECONDS: float = 60.0
    _last_attempt_at: float | None = None
    _background_in_flight: bool = False
    _background_task: asyncio.Task[None] | None = None

    def __new__(
        cls: type["IPInfoManager"],
        token: str,
        db_path: Path | None = None,
        max_age: int = 86400,
    ) -> "IPInfoManager":
        if not token:
            raise ValueError("IPInfo token is required!")

        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.token = token
            cls._instance.db_path = db_path or Path("data/ipinfo/country_asn.mmdb")
            cls._instance.reader = None
            cls._instance.redis_handler = None
            cls._instance.agent_handler = None
            cls._instance.logger = logging.getLogger("guard_core.handlers.ipinfo")
            cls._instance._max_age = max_age
            cls._instance.last_refreshed = None
            cls._instance._initialization_attempted = False
            cls._instance._last_attempt_at = None
            cls._instance._background_in_flight = False
            cls._instance._background_task = None

        cls._instance.token = token
        if db_path is not None:
            cls._instance.db_path = db_path
        cls._instance._max_age = max_age
        return cls._instance

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

    async def initialize_agent(self, agent_handler: AgentHandlerProtocol) -> None:
        self.agent_handler = agent_handler

    def _open_database_or_none(self) -> Reader | None:
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

    def _write_database_atomically(self, content: bytes) -> None:
        tmp_path = self.db_path.with_name(self.db_path.name + ".tmp")
        try:
            with open(tmp_path, "wb") as f:
                f.write(content)
            os.replace(tmp_path, self.db_path)
        except Exception:
            if tmp_path.exists():
                tmp_path.unlink()
            raise

    def _is_backing_off(self) -> bool:
        return (
            self._last_attempt_at is not None
            and time.monotonic() - self._last_attempt_at < self._RETRY_BACKOFF_SECONDS
        )

    def schedule_database_load(self) -> None:
        if self._background_in_flight or self._is_backing_off():
            return
        self._background_in_flight = True
        load = self._load_in_background
        try:
            self._background_task = asyncio.create_task(load())
        except RuntimeError:
            self.logger.exception("Could not schedule the GeoIP database load")
            self._background_in_flight = False

    async def _load_in_background(self) -> None:
        try:
            await self.initialize()
        except Exception:
            self.logger.exception("Background GeoIP database load failed")
        finally:
            self._background_in_flight = False

    async def initialize(self) -> None:
        self._last_attempt_at = time.monotonic()
        try:
            os.makedirs(self.db_path.parent, exist_ok=True)

            if self.redis_handler:
                try:
                    cached_db = await self.redis_handler.get_key("ipinfo", "database")
                except Exception as e:
                    self.logger.warning("Cached GeoIP database unavailable: %s", e)
                    cached_db = None
                if cached_db:
                    self._write_database_atomically(
                        cached_db
                        if isinstance(cached_db, bytes)
                        else cached_db.encode("latin-1")
                    )
                    reader = self._open_database_or_none()
                    if reader is not None:
                        self._apply_opened_reader(reader)
                        return
                    await self._drop_cached_database(self.redis_handler)

            try:
                if not self.db_path.exists() or self._is_db_outdated():
                    await self._download_database()
            except Exception as e:
                self.logger.error(
                    "IPInfo database download failed, keeping existing reader: "
                    f"{_describe_download_error(e)}"
                )
                if self.agent_handler:
                    await self._send_geo_event(
                        event_type=EVENT_GEO_LOOKUP_FAILED,
                        ip_address="system",
                        action_taken="database_download_failed",
                        reason=(
                            "Failed to download IPInfo database: "
                            f"{_describe_download_error(e)}"
                        ),
                    )
                return

            if self.db_path.exists():
                self._apply_opened_reader(self._open_database_or_none())
        finally:
            self._initialization_attempted = True

    async def _drop_cached_database(self, redis_handler: RedisHandlerProtocol) -> None:
        self.logger.warning("Cached GeoIP database is unusable, downloading again")
        try:
            await redis_handler.delete("ipinfo", "database")
        except Exception as e:
            self.logger.warning("Cached GeoIP database could not be dropped: %s", e)

    async def _send_geo_event(
        self,
        event_type: str,
        ip_address: str,
        action_taken: str,
        reason: str,
        **kwargs: Any,
    ) -> None:
        if not self.agent_handler:
            return

        try:
            from guard_core._pydantic_plugin_mute import get_telemetry_model

            SecurityEvent = get_telemetry_model("SecurityEvent")

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=event_type,
                ip_address=ip_address,
                action_taken=action_taken,
                reason=reason,
                rule_type=kwargs.get("rule_type"),
                handler_name=_IPINFO_HANDLER_NAME,
                metadata=kwargs,
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error(f"Failed to send geo event to agent: {e}")

    async def _download_database(self) -> None:
        base_url = "https://ipinfo.io/data/free/country_asn.mmdb"
        headers = {"Authorization": f"Bearer {self.token}"}
        retries = self._download_retries
        backoff = 1

        async with aiohttp.ClientSession() as session:
            for attempt in range(retries):
                try:
                    response = await session.get(base_url, headers=headers)
                    response.raise_for_status()
                    content = await response.read()
                    self._write_database_atomically(content)

                    if self.redis_handler is not None:
                        try:
                            with open(self.db_path, "rb") as f:
                                db_content = f.read().decode("latin-1")
                            await self.redis_handler.set_key(
                                "ipinfo",
                                "database",
                                db_content,
                                ttl=self._max_age,
                            )
                        except Exception as e:
                            self.logger.warning(
                                "Failed to cache GeoIP database in Redis: %s", e
                            )
                    return
                except Exception:
                    if attempt == retries - 1:
                        raise
                    await self._sleep(backoff)
                    backoff *= 2

    async def _sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)

    def _is_db_outdated(self) -> bool:
        if not self.db_path.exists():
            return True

        age = time.time() - self.db_path.stat().st_mtime
        return age > self._max_age

    def get_country(self, ip: str) -> str | None:
        if not self.reader:
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
            return None

        try:
            result = self.reader.get(ip)
            if isinstance(result, dict) and "country" in result:
                country = result.get("country")
                return str(country) if country is not None else None
            return None
        except Exception as e:
            if self.agent_handler:
                import asyncio

                coro = self._send_geo_event(
                    event_type=EVENT_GEO_LOOKUP_FAILED,
                    ip_address=ip,
                    action_taken="lookup_failed",
                    reason=f"Geographic lookup failed: {type(e).__name__}",
                )
                try:
                    asyncio.create_task(coro)
                except Exception:
                    coro.close()
            return None

    async def check_country_access(
        self,
        ip: str,
        blocked_countries: list[str],
        whitelist_countries: list[str] | None = None,
    ) -> tuple[bool, str | None]:
        country = self.get_country(ip)

        if not country:
            if whitelist_countries:
                return False, None
            return True, None

        if whitelist_countries and country not in whitelist_countries:
            await self._send_geo_event(
                event_type=EVENT_COUNTRY_BLOCKED,
                ip_address=ip,
                action_taken="request_blocked",
                reason=f"Country {country} not in allowed list",
                country=country,
                rule_type="country_whitelist",
            )
            return False, country

        if country in blocked_countries:
            await self._send_geo_event(
                event_type=EVENT_COUNTRY_BLOCKED,
                ip_address=ip,
                action_taken="request_blocked",
                reason=f"Country {country} is blocked",
                country=country,
                rule_type="country_blacklist",
            )
            return False, country

        return True, country

    def close(self) -> None:
        if self.reader:
            self.reader.close()

    async def refresh(self) -> None:
        try:
            await self._download_database()
        except Exception as e:
            self.logger.error(f"IPInfo refresh failed: {_describe_download_error(e)}")
            return
        finally:
            self._initialization_attempted = True

        if not self.db_path.exists():
            return

        reader = self._open_database_or_none()
        if reader is None:
            return

        self.close()
        self.reader = reader
        self.last_refreshed = datetime.now(timezone.utc)

    async def initialize_redis(self, redis_handler: RedisHandlerProtocol) -> None:
        self.redis_handler = redis_handler
        await self.initialize()
