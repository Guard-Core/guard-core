import pytest

from guard_core._security_config_geo_validators import (
    _normalized_country_value,
    _resolve_geo_ip_handler,
)
from guard_core.sync.utils import _ip_in_list


def test_an_ip_list_lookup_refuses_a_value_that_is_not_an_ip_address() -> None:
    with pytest.raises(TypeError, match="IPv4Address or an IPv6Address"):
        _ip_in_list("10.0.0.1", "10.0.0.1", ["10.0.0.0/8"])


def test_a_country_value_that_is_not_iterable_is_a_type_error() -> None:
    with pytest.raises(TypeError, match="iterable of country codes"):
        _normalized_country_value(None)


def test_a_non_text_ipinfo_token_reaches_the_manager_as_text() -> None:
    resolved = _resolve_geo_ip_handler(
        blocked_countries=frozenset({"CN"}),
        whitelist_countries=frozenset(),
        geo_ip_handler=None,
        ipinfo_token=5,
        ipinfo_db_path=None,
        ipinfo_download_url="https://example.invalid/geo.mmdb",
        geo_ip_db_max_age=1,
    )
    assert getattr(resolved, "token", None) == "5"
