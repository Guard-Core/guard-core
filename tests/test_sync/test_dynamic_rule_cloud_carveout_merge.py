from collections.abc import Iterator
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.models import DynamicRules, SyncSecurityConfig
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager
from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler


@pytest.fixture(autouse=True)
def reset_singleton() -> Iterator[None]:
    DynamicRuleManager._instance = None
    yield
    DynamicRuleManager._instance = None


def _selectors_after_applying(static: set[str], dynamic: set[str]) -> frozenset[str]:
    config = SyncSecurityConfig(
        enable_redis=False,
        geo_ip_handler=MagicMock(spec=SyncGeoIPHandler),
        block_cloud_providers=static,
    )
    rules: dict[str, Any] = {
        "rule_id": "R",
        "version": 1,
        "timestamp": datetime.now(timezone.utc),
        "blocked_cloud_providers": dynamic,
    }
    DynamicRuleManager(config)._apply_rules(DynamicRules(**rules))
    return frozenset(config.block_cloud_providers or ())


@pytest.mark.parametrize(
    ("static", "dynamic", "expected"),
    [
        ({"GCP:!us-central1"}, {"GCP"}, {"GCP"}),
        ({"GCP"}, {"GCP:!us-central1"}, {"GCP"}),
        ({"GCP:!us-central1"}, {"GCP:!us-central1"}, {"GCP:!us-central1"}),
        ({"GCP:!us-central1"}, {"GCP:!us-east1"}, {"GCP"}),
        (
            {"GCP:!us-central1", "GCP:!us-east1"},
            {"GCP:!us-east1"},
            {"GCP:!us-east1"},
        ),
        ({"GCP:!us-central1"}, {"AWS"}, {"GCP:!us-central1", "AWS"}),
    ],
)
def test_a_region_is_carved_out_only_when_every_blocking_source_carves_it(
    static: set[str], dynamic: set[str], expected: set[str]
) -> None:
    assert _selectors_after_applying(static, dynamic) == frozenset(expected)
