import json
from pathlib import Path
from typing import Any

from guard_core.models import SyncSecurityConfig
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest, declare_route

WORDLISTS = (
    next(p for p in Path(__file__).resolve().parents if p.name == "tests") / "wordlists"
)
BASELINE = json.loads(
    (WORDLISTS / "quickhits_flagged_5c38dc89.json").read_text("utf-8")
)["flagged"]
NAME_ONLY_FAMILIES = {"recon", "cms_probing"}


def _verdict(name: str, path_params: Any) -> tuple[bool, set[str]]:
    request = SyncMockGuardRequest(path=f"/files/{name}")
    declare_route(request, "/files/{name:path}")
    route_config = None
    if path_params is not None:
        route_config = RouteConfig()
        route_config.excluded_detection_path_params = path_params
    result = detect_penetration_attempt(
        request, SyncSecurityConfig(enable_redis=False), route_config
    )
    return result.is_threat, set(result.threat_categories)


def test_quickhits_sensitive_entries_in_a_declared_catch_all_stay_flagged() -> None:
    still_flagged = 0
    lost = []
    for name in BASELINE:
        flagged, categories = _verdict(name, None)
        if not flagged or categories <= NAME_ONLY_FAMILIES:
            continue
        declared_flagged, _ = _verdict(name, {"name"})
        still_flagged += declared_flagged
        if not declared_flagged:
            lost.append(name)
    assert lost == []
    assert still_flagged > 0
