from __future__ import annotations

from guard_core.core.events.event_types import CHECK_NAME_VALUES
from guard_core.decorators import SecurityDecorator
from guard_core.models import SecurityConfig
from tests.live_smoke.registry import SCENARIOS


def _decorator_method_names() -> set[str]:
    return {
        name
        for name in dir(SecurityDecorator)
        if not name.startswith("_") and callable(getattr(SecurityDecorator, name))
    }


def _required_names() -> set[str]:
    return (
        set(REQUIRED_SURFACES)
        | set(SecurityConfig.model_fields)
        | _decorator_method_names()
        | set(CHECK_NAME_VALUES)
    )


REQUIRED_SURFACES = frozenset(
    {
        "surface:websocket_guard",
        "surface:pure_asgi_middleware",
        "surface:status_route",
        "surface:lifespan_edges",
        "surface:middleware_introspection",
        "surface:static_files_bypass",
        "surface:http_methods",
        "surface:streaming_response",
        "surface:building_block_ip_access",
        "surface:cidr_rules",
        "surface:admin_routes",
        "surface:manual_unban",
        "surface:building_block_behavior",
        "surface:building_block_rate_limit_manager",
        "surface:building_block_security_headers_manager",
        "surface:building_block_bounded_readers",
        "surface:building_block_endpoint_key_problems",
        "surface:custom_pattern_api",
        "surface:detection_family_matrix",
        "surface:default_security_headers",
        "surface:two_workers_share_the_rate_limit",
        "surface:two_workers_share_the_ban",
    }
)


def test_every_field_method_and_check_name_has_a_live_scenario() -> None:
    covered: set[str] = set()
    for item in SCENARIOS:
        covered |= item.covers

    missing = sorted(_required_names() - covered)
    assert not missing, (
        "no live-smoke scenario covers these SecurityConfig fields / "
        "SecurityDecorator methods / pipeline check names "
        f"({len(missing)} total):\n" + "\n".join(f"  - {name}" for name in missing)
    )
