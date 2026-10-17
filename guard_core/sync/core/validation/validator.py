import hashlib
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network

from cachetools import TTLCache

from guard_core.sync._utils.request_logging import redact_endpoint_for_display
from guard_core.sync.core.events.event_types import EVENT_PATH_EXCLUDED
from guard_core.sync.core.validation.context import ValidationContext
from guard_core.sync.core.validation.path_matching import (
    normalize_exclude_paths,
    path_matches_exclusions,
    router_path_for_exclusion,
)
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


class RequestValidator:
    def __init__(self, context: ValidationContext) -> None:
        self.context = context
        self._path_excluded_event_cache: TTLCache[str, bool] = TTLCache(
            maxsize=1000, ttl=300
        )
        self._normalized_exclude_paths: tuple[str, ...] = ()
        self._normalized_exclude_paths_source: tuple[str, ...] | None = None

    def is_request_https(self, request: SyncGuardRequest) -> bool:
        is_https = request.url_scheme == "https"

        if (
            self.context.config.trust_x_forwarded_proto
            and self.context.config.trusted_proxies
            and request.client_host
        ):
            if self.is_trusted_proxy(request.client_host):
                forwarded_proto = request.headers.get("X-Forwarded-Proto", "")
                is_https = is_https or forwarded_proto.lower() == "https"

        return is_https

    def is_trusted_proxy(self, connecting_ip: str) -> bool:
        for proxy in self.context.config.trusted_proxies:
            if "/" not in proxy:
                if connecting_ip == proxy:
                    return True
            else:
                if ip_address(connecting_ip) in ip_network(proxy, strict=False):
                    return True
        return False

    def check_time_window(self, time_restrictions: dict[str, str]) -> bool:
        try:
            start_time = time_restrictions["start"]
            end_time = time_restrictions["end"]

            current_time = datetime.now(timezone.utc)
            current_hour_minute = current_time.strftime("%H:%M")

            if start_time > end_time:
                return (
                    current_hour_minute >= start_time or current_hour_minute <= end_time
                )
            else:
                return start_time <= current_hour_minute <= end_time

        except Exception as e:
            self.context.logger.error(f"Error checking time window: {e!s}")
            return True

    def _current_normalized_exclude_paths(self) -> tuple[str, ...]:
        config = self.context.config
        current_source = (*config.exclude_paths, *(("/",) * config.exclude_all_paths))
        if current_source != self._normalized_exclude_paths_source:
            self._normalized_exclude_paths = normalize_exclude_paths(current_source)
            self._normalized_exclude_paths_source = current_source
        return self._normalized_exclude_paths

    def is_path_excluded(self, request: SyncGuardRequest) -> bool:
        normalized_path = router_path_for_exclusion(request.url_path)
        if normalized_path is None:
            return False

        if not path_matches_exclusions(
            normalized_path, self._current_normalized_exclude_paths()
        ):
            return False

        cache_key = hashlib.sha256(normalized_path.encode()).hexdigest()
        if self._path_excluded_event_cache.get(cache_key) is None:
            self._path_excluded_event_cache[cache_key] = True
            safe_path = redact_endpoint_for_display(
                str(request.url_path),
                self.context.config.log_sensitive_params,
                self.context.config.log_sensitive_body_fields,
                self.context.config.log_sensitive_headers,
            )
            self.context.event_bus.send_middleware_event(
                event_type=EVENT_PATH_EXCLUDED,
                request=request,
                action_taken="security_checks_bypassed",
                reason=f"Path {safe_path} excluded from security checks",
                excluded_path=safe_path,
                configured_exclusions=self.context.config.exclude_paths,
            )

        return True
