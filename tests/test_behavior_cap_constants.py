import pytest

from guard_core import _tracking_caps
from guard_core.core.checks import helpers
from guard_core.handlers import _behavior_throttle, behavior_handler, ratelimit_handler
from guard_core.models import SecurityConfig


@pytest.mark.parametrize(
    ("module", "constant", "field"),
    [
        (behavior_handler, "_MAX_TRACKED_ENDPOINTS", "behavior_max_tracked_endpoints"),
        (
            behavior_handler,
            "_MAX_TRACKED_CLIENTS_PER_ENDPOINT",
            "behavior_max_tracked_clients_per_endpoint",
        ),
        (
            _behavior_throttle,
            "MAX_TRACKED_BUCKETS",
            "behavior_throttle_max_tracked_buckets",
        ),
        (
            _behavior_throttle,
            "MAX_TRACKED_CLIENTS_PER_BUCKET",
            "behavior_throttle_max_tracked_clients_per_bucket",
        ),
        (_behavior_throttle, "MAX_TRIP_MARKERS", "behavior_throttle_max_trip_markers"),
        (
            ratelimit_handler,
            "_MAX_TRACKED_RATE_LIMIT_KEYS",
            "rate_limit_max_tracked_keys",
        ),
        (helpers, "_MAX_TRACKED_SUSPICIOUS_IPS", "ban_counters_max_tracked_ips"),
    ],
)
def test_the_module_constant_is_the_default_of_its_field(
    monkeypatch: pytest.MonkeyPatch, module: object, constant: str, field: str
) -> None:
    assert getattr(module, constant) == 10_000
    assert getattr(SecurityConfig(), field) == 10_000
    monkeypatch.setattr(_tracking_caps, constant, 7)
    assert getattr(SecurityConfig(), field) == 7
    assert getattr(SecurityConfig(**{field: 9}), field) == 9
