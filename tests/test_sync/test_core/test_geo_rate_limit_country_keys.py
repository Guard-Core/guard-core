from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
from tests.test_sync.test_core.conftest import (
    build_route_pipeline,
    fixed_country_geo_ip,
    send_request,
)

IP = "198.51.100.77"


def _config(**settings: object) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=True,
        rate_limit=1000,
        **settings,
    )


def _statuses(
    pipeline: SecurityCheckPipeline, route_id: str, count: int
) -> list[int | None]:
    statuses: list[int | None] = []
    for _ in range(count):
        response = send_request(pipeline, route_id, ip=IP)
        statuses.append(None if response is None else response.status_code)
    return statuses


def test_lowercase_country_keys_limit_like_uppercase_ones() -> None:
    config = _config()
    geo = fixed_country_geo_ip("US")
    config.geo_ip_handler = geo
    pipeline, _, route_id = build_route_pipeline(
        config, lambda d: d.geo_rate_limit({"us": (1, 60)}), geo_ip_handler=geo
    )

    assert _statuses(pipeline, route_id, 3) == [None, 429, 429]


def test_the_wildcard_key_still_works() -> None:
    config = _config()
    geo = fixed_country_geo_ip("DE")
    config.geo_ip_handler = geo
    pipeline, _, route_id = build_route_pipeline(
        config,
        lambda d: d.geo_rate_limit({"us": (100, 60), "*": (1, 60)}),
        geo_ip_handler=geo,
    )

    assert _statuses(pipeline, route_id, 3) == [None, 429, 429]


def test_the_geo_limit_reads_the_handler_the_ip_checks_read() -> None:
    config = _config()
    geo = fixed_country_geo_ip("US")
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.geo_rate_limit({"US": (1, 60)}), geo_ip_handler=geo
    )

    assert config.geo_ip_handler is None
    assert middleware.geo_ip_handler is geo
    assert _statuses(pipeline, route_id, 3) == [None, 429, 429]
