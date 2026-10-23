import logging
import threading
from collections import OrderedDict
from collections.abc import Callable
from typing import Any

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.sampling import observe_counted_key

EVICTION_WARNING_WINDOW_SECONDS = 60
_EVICTION_KINDS_TRACKED = 8

_RULE_HIT_INDEX_KIND = "rule_hit_index"
_CAP_FIELD_BY_KIND = {
    "endpoint": "behavior_max_tracked_endpoints",
    "endpoint_client": "behavior_max_tracked_clients_per_endpoint",
    "throttle_bucket": "behavior_throttle_max_tracked_buckets",
    "throttle_client": "behavior_throttle_max_tracked_clients_per_bucket",
    "trip_marker": "behavior_throttle_max_trip_markers",
    _RULE_HIT_INDEX_KIND: "behavior_max_tracked_endpoints",
}


class BehaviorEvictionMixin:
    """Tells the operator when a behavior tracking cap drops a live entry.

    The tracker's bounded stores evict silently; each eviction here is sampled
    once per kind per ``EVICTION_WARNING_WINDOW_SECONDS`` into one WARNING (no
    client address) and one ``behavior_bucket_evicted`` event that carries how many
    evictions of that kind were not reported since the last one.
    """

    config: SyncSecurityConfig
    _lock: threading.Lock
    agent_handler: Any
    logger: logging.Logger
    _send_behavior_event: Callable[..., None]

    def _init_eviction_reporting(self) -> None:
        self._eviction_samples: OrderedDict[str, tuple[float, int]] = OrderedDict()
        self._eviction_samples_lock = threading.Lock()
        # (kind, value) of every entry a cap dropped, until the request that
        # caused it reports them: the value is truthy when the entry was live.
        self._evicted_values: list[tuple[str, Any]] = []

    def _report_evictions(self, client_ip: str) -> None:
        with self._lock:
            pending, self._evicted_values = self._evicted_values, []
        for kind, value in pending:
            if value:
                self._report_eviction(kind, client_ip)

    def _report_eviction(self, kind: str, client_ip: str) -> None:
        refused = kind == _RULE_HIT_INDEX_KIND
        store = "redis" if refused else "memory"
        outcome = "refused" if refused else "evicted"
        cap = getattr(self.config, _CAP_FIELD_BY_KIND[kind])
        sampled, suppressed, _ = observe_counted_key(
            self._eviction_samples,
            self._eviction_samples_lock,
            kind,
            window=EVICTION_WARNING_WINDOW_SECONDS,
            max_tracked=_EVICTION_KINDS_TRACKED,
        )
        if not sampled:
            return
        self.logger.warning(
            "Behavior tracking %s an entry of kind %s (%s store) because it holds "
            "%d entries; raise SecurityConfig.%s if this is expected load. "
            "%d earlier %s of this kind were not logged. Logged once a minute "
            "per kind.",
            outcome,
            kind,
            store,
            cap,
            _CAP_FIELD_BY_KIND[kind],
            suppressed,
            "refusals" if refused else "evictions",
        )
        from guard_core.sync.core.events.event_types import (
            EVENT_BEHAVIOR_BUCKET_EVICTED,
        )

        if (
            self.agent_handler
            and self.config.agent_enable_events
            and EVENT_BEHAVIOR_BUCKET_EVICTED not in self.config.muted_event_types
        ):
            self._send_behavior_event(
                event_type=EVENT_BEHAVIOR_BUCKET_EVICTED,
                ip_address=client_ip,
                action_taken=outcome,
                reason=(
                    f"Behavior tracking {outcome} an entry of kind {kind} because "
                    f"the {store} store holds {cap} entries"
                ),
                kind=kind,
                cap=cap,
                store=store,
                outcome=outcome,
                suppressed_count=suppressed,
            )
