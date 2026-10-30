from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.route_gate import ROUTE_TEMPLATE_STATE_ATTR
from guard_core.sync.core.events import metrics as metrics_module
from guard_core.sync.core.events.metrics import MetricsCollector
from tests.test_sync.conftest import SyncMockGuardRequest


def _collector() -> MetricsCollector:
    config = SyncSecurityConfig(agent_enable_metrics=True)
    return MetricsCollector(MagicMock(), config)


def test_a_matched_route_reports_its_template_not_the_raw_path() -> None:
    collector = _collector()
    request = SyncMockGuardRequest(path="/users/42")
    setattr(request.state, ROUTE_TEMPLATE_STATE_ATTR, "/users/{id}")

    assert collector._metric_endpoint(request) == "/users/{id}"
    assert collector._unmatched_endpoints == set()


def test_unmatched_paths_share_one_series_past_the_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(metrics_module, "MAX_UNMATCHED_METRIC_ENDPOINTS", 3)
    collector = _collector()

    seen = [
        collector._metric_endpoint(SyncMockGuardRequest(path=f"/p{i}"))
        for i in range(6)
    ]

    assert seen == ["/p0", "/p1", "/p2", "other", "other", "other"]
    assert collector._metric_endpoint(SyncMockGuardRequest(path="/p1")) == "/p1"


def test_collect_request_metrics_tags_every_metric_with_the_bounded_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collector = _collector()
    endpoints: list[str] = []

    def record(
        metric_type: str, value: float, tags: dict[str, str] | None = None
    ) -> None:
        endpoints.append((tags or {})["endpoint"])

    monkeypatch.setattr(collector, "send_metric", record)

    collector.collect_request_metrics(SyncMockGuardRequest(path="/health"), 0.01, 200)

    assert endpoints == ["/health", "/health"]
