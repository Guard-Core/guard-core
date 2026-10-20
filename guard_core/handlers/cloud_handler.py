import asyncio
import ipaddress
import logging
import time
from collections.abc import Awaitable, Callable, Collection
from datetime import datetime, timezone
from typing import Any

from guard_core.handlers._cloud_azure_fetch import (
    _AZURE_DOWNLOAD_ATTEMPT_TIMEOUT_SECONDS,
    _AZURE_DOWNLOAD_MAX_ATTEMPTS,
    _AZURE_DOWNLOAD_MAX_ELAPSED_SECONDS,
    _AZURE_DOWNLOAD_RETRY_DELAY_SECONDS,
    _AZURE_PAGE_FETCH_TIMEOUT_SECONDS,
    _AZURE_SERVICE_TAGS_DATE_PATTERN,
    _AZURE_SERVICE_TAGS_STALE_WARNING_DAYS,
    _AZURE_SERVICE_TAGS_URL_PATTERN,
    _AZURE_TRUSTED_DOWNLOAD_HOST,
    _download_azure_service_tags,
    _extract_azure_download_url,
    _extract_failover_link_url,
    _extract_generic_json_url,
    _extract_newest_service_tags_url,
    _is_trusted_azure_download_url,
    _parse_service_tags_date,
    _service_tags_sort_key,
    _warn_if_service_tags_url_is_stale,
    fetch_azure_ip_ranges,
)
from guard_core.handlers._cloud_provider_fetchers import (
    fetch_aws_ip_ranges,
    fetch_digitalocean_ip_ranges,
    fetch_gcp_ip_ranges,
    fetch_linode_ip_ranges,
    fetch_vultr_ip_ranges,
)
from guard_core.handlers._cloud_provider_registry import (
    _ALL_PROVIDERS,
    _bare_provider_names,
    _decode_cached,
    _encode_cached,
    _parse_cloud_selectors,
)
from guard_core.handlers._cloud_range_index import NetworkIndex
from guard_core.handlers.cloud_ip_stores import InMemoryCloudIpStore
from guard_core.protocols.agent_protocol import AgentHandlerProtocol
from guard_core.protocols.cloud_ip_store_protocol import CloudIpStoreProtocol
from guard_core.protocols.redis_protocol import RedisHandlerProtocol

__all__ = [
    "_ALL_PROVIDERS",
    "_AZURE_DOWNLOAD_ATTEMPT_TIMEOUT_SECONDS",
    "_AZURE_DOWNLOAD_MAX_ATTEMPTS",
    "_AZURE_DOWNLOAD_MAX_ELAPSED_SECONDS",
    "_AZURE_DOWNLOAD_RETRY_DELAY_SECONDS",
    "_AZURE_PAGE_FETCH_TIMEOUT_SECONDS",
    "_AZURE_SERVICE_TAGS_DATE_PATTERN",
    "_AZURE_SERVICE_TAGS_STALE_WARNING_DAYS",
    "_AZURE_SERVICE_TAGS_URL_PATTERN",
    "_AZURE_TRUSTED_DOWNLOAD_HOST",
    "CloudManager",
    "_bare_provider_names",
    "_decode_cached",
    "_download_azure_service_tags",
    "_encode_cached",
    "_extract_azure_download_url",
    "_extract_failover_link_url",
    "_extract_generic_json_url",
    "_extract_newest_service_tags_url",
    "_is_trusted_azure_download_url",
    "_parse_cloud_selectors",
    "_parse_service_tags_date",
    "_service_tags_sort_key",
    "_warn_if_service_tags_url_is_stale",
    "cloud_handler",
    "fetch_aws_ip_ranges",
    "fetch_azure_ip_ranges",
    "fetch_digitalocean_ip_ranges",
    "fetch_gcp_ip_ranges",
    "fetch_linode_ip_ranges",
    "fetch_vultr_ip_ranges",
]

logger = logging.getLogger("guard_core.handlers.cloud")


async def _fetch_provider_ranges(
    provider: str,
) -> tuple[set[ipaddress.IPv4Network | ipaddress.IPv6Network], dict[str, str]]:
    fetchers = {
        "AWS": fetch_aws_ip_ranges,
        "GCP": fetch_gcp_ip_ranges,
        "Azure": fetch_azure_ip_ranges,
        "DigitalOcean": fetch_digitalocean_ip_ranges,
        "Linode": fetch_linode_ip_ranges,
        "Vultr": fetch_vultr_ip_ranges,
    }
    result: Any = await fetchers[provider]()
    if isinstance(result, tuple):
        return result
    return result, {}


_CLOUD_HANDLER_NAME = "cloud"


class CloudManager:
    _instance = None
    ip_ranges: dict[str, set[ipaddress.IPv4Network | ipaddress.IPv6Network]]
    network_regions: dict[str, dict[str, str]]
    redis_handler: RedisHandlerProtocol | None = None
    agent_handler: AgentHandlerProtocol | None = None
    logger: logging.Logger
    last_updated: dict[str, datetime | None]
    _store: CloudIpStoreProtocol | None
    _refresh_task: asyncio.Task[None] | None
    _refresh_in_flight: bool
    _refresh_lock: asyncio.Lock
    _empty_ranges_warned_at: dict[str, float]
    _range_indexes: dict[str, NetworkIndex]
    _EMPTY_RANGES_WARNING_COOLDOWN = 300.0

    def __new__(cls: type["CloudManager"]) -> "CloudManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.ip_ranges = {
                "AWS": set(),
                "GCP": set(),
                "Azure": set(),
                "DigitalOcean": set(),
                "Linode": set(),
                "Vultr": set(),
            }
            cls._instance.network_regions = {
                provider: {} for provider in _ALL_PROVIDERS
            }
            cls._instance.last_updated = {provider: None for provider in _ALL_PROVIDERS}
            cls._instance.redis_handler = None
            cls._instance.agent_handler = None
            cls._instance.logger = logging.getLogger("guard_core.handlers.cloud")
            cls._instance._store = InMemoryCloudIpStore()
            cls._instance._refresh_task = None
            cls._instance._refresh_in_flight = False
            cls._instance._refresh_lock = asyncio.Lock()
            cls._instance._empty_ranges_warned_at = {}
            cls._instance._range_indexes = {}
        return cls._instance

    def _index_of(self, provider: str) -> NetworkIndex:
        networks = self.ip_ranges[provider]
        index = self._range_indexes.get(provider)
        if index is None or not index.describes(networks):
            index = NetworkIndex(networks)
            self._range_indexes[provider] = index
        return index

    def set_store(self, store: CloudIpStoreProtocol) -> None:
        self._store = store

    async def schedule_refresh(
        self,
        providers: set[str] = _ALL_PROVIDERS,
        ttl: int = 3600,
        refresh: Callable[[], Awaitable[None]] | None = None,
    ) -> bool:
        """Refresh cloud IP ranges in the background without blocking the caller.

        Cloud-provider range fetches are multi-second network calls; running them
        inline on the request path blocks request handling for every caller. This
        fires the refresh as a single-flight background task instead: while one is in
        flight, further calls are no-ops. The gate is lock-guarded so concurrent
        callers (multi-threaded sync deployments) can't start duplicate refreshes.
        Passing ``refresh`` runs that callable as the background refresh instead of
        this manager's own ``refresh_async``, middleware callers use it to keep
        adapter overrides of ``refresh_cloud_ip_ranges`` on the periodic path.
        Returns True if a task was started.
        """

        async def _run_refresh() -> None:
            try:
                if refresh is None:
                    await self.refresh_async(providers, ttl=ttl)
                else:
                    await refresh()
            except Exception:
                self.logger.exception("Background cloud IP refresh failed")
            finally:
                self._refresh_in_flight = False

        async with self._refresh_lock:
            if self._refresh_in_flight:
                return False
            self._refresh_in_flight = True
            try:
                self._refresh_task = asyncio.create_task(_run_refresh())
            except RuntimeError:
                self.logger.exception("Could not schedule cloud IP refresh")
                self._refresh_in_flight = False
                return False
            return True

    def _log_range_changes(
        self,
        provider: str,
        old_ranges: set[ipaddress.IPv4Network | ipaddress.IPv6Network],
        new_ranges: set[ipaddress.IPv4Network | ipaddress.IPv6Network],
    ) -> None:
        if old_ranges == new_ranges:
            return
        added = new_ranges - old_ranges
        removed = old_ranges - new_ranges
        self.logger.info(
            f"Cloud IP range update for {provider}: "
            f"+{len(added)} added, -{len(removed)} removed"
        )

    async def _refresh_providers(
        self, providers: Collection[str] = _ALL_PROVIDERS
    ) -> None:
        for provider in _bare_provider_names(providers):
            try:
                ranges, regions = await _fetch_provider_ranges(provider)
                if ranges:
                    old_ranges = self.ip_ranges.get(provider, set())
                    self._log_range_changes(provider, old_ranges, ranges)
                    self.ip_ranges[provider] = ranges
                    self.network_regions[provider] = regions
                    self.last_updated[provider] = datetime.now(timezone.utc)
            except Exception as e:
                self.logger.error(f"Failed to fetch {provider} IP ranges: {str(e)}")
                if provider not in self.ip_ranges:
                    self.ip_ranges[provider] = set()
                    self.network_regions[provider] = {}

    async def initialize_redis(
        self,
        redis_handler: RedisHandlerProtocol,
        providers: Collection[str] = _ALL_PROVIDERS,
        ttl: int = 3600,
    ) -> None:
        self.redis_handler = redis_handler
        if isinstance(self._store, InMemoryCloudIpStore):
            from guard_core.handlers.cloud_ip_stores import RedisCloudIpStore

            self._store = RedisCloudIpStore(redis_handler)
        await self.refresh_async(providers, ttl=ttl)

    async def initialize_agent(self, agent_handler: AgentHandlerProtocol) -> None:
        self.agent_handler = agent_handler

    async def refresh(self, providers: Collection[str] = _ALL_PROVIDERS) -> None:
        if self.redis_handler is not None:
            raise RuntimeError("Use refresh_async() when Redis is enabled")
        await self._refresh_providers(providers)

    async def refresh_async(
        self, providers: Collection[str] = _ALL_PROVIDERS, ttl: int = 3600
    ) -> None:
        if self._store is None:
            await self._refresh_providers_via_redis_handler(providers, ttl=ttl)
            return

        for provider in _bare_provider_names(providers):
            try:
                cached = await self._store.get(provider)
                if cached is not None:
                    nets, regions = _decode_cached(cached)
                    self.ip_ranges[provider] = nets
                    self.network_regions[provider] = regions
                    continue

                ranges, regions = await _fetch_provider_ranges(provider)
                if ranges:
                    await self._store.set(
                        provider,
                        _encode_cached(ranges, regions),
                        ttl=ttl,
                    )
                    old_ranges = self.ip_ranges.get(provider, set())
                    self._log_range_changes(provider, old_ranges, ranges)
                    self.ip_ranges[provider] = ranges
                    self.network_regions[provider] = regions
                    self.last_updated[provider] = datetime.now(timezone.utc)
            except Exception as e:
                self.logger.error(f"Failed to refresh {provider} IP ranges: {str(e)}")
                if provider not in self.ip_ranges:
                    self.ip_ranges[provider] = set()

    async def _refresh_providers_via_redis_handler(
        self, providers: Collection[str], ttl: int = 3600
    ) -> None:
        if self.redis_handler is None:
            await self._refresh_providers(providers)
            return

        for provider in _bare_provider_names(providers):
            try:
                cached = await self.redis_handler.get_key("cloud_ranges_v2", provider)
                if cached:
                    nets, regions = _decode_cached(set(cached.split(",")))
                    self.ip_ranges[provider] = nets
                    self.network_regions[provider] = regions
                    continue

                ranges, regions = await _fetch_provider_ranges(provider)
                if ranges:
                    await self.redis_handler.set_key(
                        "cloud_ranges_v2",
                        provider,
                        ",".join(sorted(_encode_cached(ranges, regions))),
                        ttl=ttl,
                    )
                    old_ranges = self.ip_ranges.get(provider, set())
                    self._log_range_changes(provider, old_ranges, ranges)
                    self.ip_ranges[provider] = ranges
                    self.network_regions[provider] = regions
                    self.last_updated[provider] = datetime.now(timezone.utc)
            except Exception as e:
                self.logger.error(f"Failed to refresh {provider} IP ranges: {str(e)}")
                if provider not in self.ip_ranges:
                    self.ip_ranges[provider] = set()

    def _warn_empty_ranges(self, provider: str) -> None:
        now = time.monotonic()
        warned_at = self._empty_ranges_warned_at.get(provider)
        if (
            warned_at is not None
            and now - warned_at < self._EMPTY_RANGES_WARNING_COOLDOWN
        ):
            return
        self._empty_ranges_warned_at[provider] = now
        self.logger.warning(
            "Cloud IP ranges for %s are not populated yet; is_cloud_ip is "
            "returning not-blocked for every %s IP until the initial fetch "
            "completes.",
            provider,
            provider,
        )

    def is_cloud_ip(self, ip: str, providers: set[str] = _ALL_PROVIDERS) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            blocked, carveouts = _parse_cloud_selectors(providers)
            for provider in blocked:
                if provider not in self.ip_ranges:
                    continue
                if not self.ip_ranges[provider]:
                    self._warn_empty_ranges(provider)
                allowed_regions = carveouts.get(provider)
                provider_regions = self.network_regions.get(provider, {})
                for network in self._index_of(provider).containing(ip_obj):
                    if allowed_regions and (
                        provider_regions.get(str(network)) in allowed_regions
                    ):
                        continue
                    return True
            return False
        except ValueError:
            self.logger.error(f"Invalid IP address: {ip}")
            return False

    def get_status(self) -> dict[str, dict[str, Any]]:
        return {
            provider: {
                "ready": bool(self.ip_ranges.get(provider)),
                "last_refreshed": self.last_updated.get(provider),
                "entries": len(self.ip_ranges.get(provider, set())),
            }
            for provider in _ALL_PROVIDERS
        }

    def get_cloud_provider_details(
        self, ip: str, providers: set[str] = _ALL_PROVIDERS
    ) -> tuple[str, str] | None:
        try:
            ip_obj = ipaddress.ip_address(ip)
            for provider in _bare_provider_names(providers):
                if provider in self.ip_ranges:
                    for network in self._index_of(provider).containing(ip_obj):
                        return (provider, str(network))
            return None
        except ValueError:
            self.logger.error(f"Invalid IP address: {ip}")
            return None

    async def send_cloud_detection_event(
        self,
        ip: str,
        provider: str,
        network: str,
        action_taken: str = "request_blocked",
        **attribution: Any,
    ) -> None:
        from guard_core.core.events.event_types import EVENT_CLOUD_BLOCKED

        if not self.agent_handler:
            return

        await self._send_cloud_event(
            event_type=EVENT_CLOUD_BLOCKED,
            ip_address=ip,
            action_taken=action_taken,
            reason=f"IP belongs to blocked cloud provider: {provider}",
            cloud_provider=provider,
            network=network,
            **attribution,
        )

    async def _send_cloud_event(
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
                handler_name=_CLOUD_HANDLER_NAME,
                metadata=kwargs,
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error(f"Failed to send cloud event to agent: {e}")


cloud_handler = CloudManager()
