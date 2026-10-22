import hashlib
from datetime import datetime

from cachetools import TTLCache

from guard_core.sync._utils.forwarded_proto import request_is_https
from guard_core.sync._utils.ip_extraction import _is_trusted_proxy
from guard_core.sync._utils.request_logging import redact_endpoint_for_display
from guard_core.sync._utils.time_window import time_window_allows
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
        return request_is_https(request, self.context.config)

    def is_trusted_proxy(self, connecting_ip: str) -> bool:
        return _is_trusted_proxy(connecting_ip, self.context.config.trusted_proxies)

    def check_time_window(self, time_restrictions: dict[str, str]) -> bool:
        return time_window_allows(time_restrictions, self.context.logger, datetime.now)

    def _current_normalized_exclude_paths(self) -> tuple[str, ...]:
        current_source = tuple(self.context.config.exclude_paths)
        if current_source != self._normalized_exclude_paths_source:
            self._normalized_exclude_paths = normalize_exclude_paths(current_source)
            self._normalized_exclude_paths_source = current_source
        return self._normalized_exclude_paths

    def is_path_excluded(self, request: SyncGuardRequest) -> bool:
        normalized_path = router_path_for_exclusion(request.url_path)
        if normalized_path is None:
            return False

        whole_app = self.context.config.exclude_all_paths is True
        if not whole_app and not path_matches_exclusions(
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
