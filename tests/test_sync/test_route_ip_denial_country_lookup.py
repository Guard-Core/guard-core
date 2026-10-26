from unittest.mock import MagicMock

from guard_core.sync.core.checks.implementations.ip_security import (
    _classify_route_ip_denial,
)
from guard_core.sync.decorators.base import RouteConfig


def _denial(country: str | None) -> tuple[str, str]:
    route_config = RouteConfig()
    route_config.blocked_countries = ["CN"]
    geo_ip_handler = MagicMock()
    geo_ip_handler.get_country.return_value = country
    return _classify_route_ip_denial(route_config, geo_ip_handler, "203.0.113.9", False)


def test_a_country_on_the_route_blocklist_is_a_block_countries_denial() -> None:
    assert _denial("CN") == ("block_countries", "country_restriction")


def test_an_unknown_country_is_an_allow_countries_denial() -> None:
    assert _denial(None) == ("allow_countries", "country_restriction")


def test_a_country_off_the_blocklist_is_an_allow_countries_denial() -> None:
    assert _denial("US") == ("allow_countries", "country_restriction")
