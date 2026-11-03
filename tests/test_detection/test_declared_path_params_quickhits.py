import json
from pathlib import Path

from guard_core.decorators.base import RouteConfig
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest, declare_route

WORDLISTS = (
    next(p for p in Path(__file__).resolve().parents if p.name == "tests") / "wordlists"
)
BASELINE = json.loads(
    (WORDLISTS / "quickhits_flagged_5c38dc89.json").read_text("utf-8")
)["flagged"]
NAME_ONLY_FAMILIES = {"recon", "cms_probing"}


async def _verdict(
    name: str, path_params: set[str] | dict[str, set[str]] | None
) -> tuple[bool, set[str]]:
    request = MockGuardRequest(path=f"/files/{name}")
    declare_route(request, "/files/{name:path}")
    route_config = None
    if path_params is not None:
        route_config = RouteConfig()
        route_config.excluded_detection_path_params = path_params
    result = await detect_penetration_attempt(
        request, SecurityConfig(enable_redis=False), route_config
    )
    return result.is_threat, set(result.threat_categories)


async def test_quickhits_sensitive_entries_in_a_declared_catch_all_stay_flagged() -> (
    None
):
    still_flagged = 0
    lost = []
    for name in BASELINE:
        flagged, categories = await _verdict(name, None)
        if not flagged or categories <= NAME_ONLY_FAMILIES:
            continue
        declared_flagged, _ = await _verdict(name, {"name"})
        still_flagged += declared_flagged
        if not declared_flagged:
            lost.append(name)
    assert lost == []
    assert still_flagged > 0
