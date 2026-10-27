from guard_core.core.checks._strike_counts import _WindowedCategoryCounts
from guard_core.core.checks._strike_forget import register_strike_middleware
from guard_core.handlers import ratelimit_handler
from guard_core.handlers._ipban_coverage import NetworkCoverage
from guard_core.handlers.ipban_handler import IPBanManager
from guard_core.models import SecurityConfig


class _Middleware:
    def __init__(self, counts: dict[str, dict[str, int]]) -> None:
        self.config = SecurityConfig(enable_redis=False)
        self.suspicious_request_counts = counts


def _coverage(*entries: str) -> NetworkCoverage:
    import ipaddress

    return NetworkCoverage([ipaddress.ip_network(e, strict=False) for e in entries])


def test_a_coverage_member_may_be_an_address_or_a_network_identity() -> None:
    coverage = _coverage("2001:db8::/32", "198.51.100.0/24")

    assert coverage.covers_member("198.51.100.7")
    assert coverage.covers_member("2001:db8:0:5::/64")
    assert coverage.covers_member("2001:db8::1")
    assert not coverage.covers_member("2001:db9::/64")
    assert not coverage.covers_member("203.0.113.1")
    assert not coverage.covers_member("not-an-address")


def test_a_network_identity_straddling_the_range_edge_is_not_covered() -> None:
    assert not _coverage("2001:db8::/96").covers_member("2001:db8::/64")


async def test_a_whitelisted_range_clears_the_strikes_of_the_identities_inside_it() -> (
    None
):
    middleware = _Middleware(
        {
            "2001:db8:0:1::/64": {"xss": 1},
            "2001:db9:0:1::/64": {"xss": 1},
            "198.51.100.10": {"xss": 1},
            "203.0.113.10": {"xss": 1},
        }
    )
    register_strike_middleware(middleware)
    ratelimit_handler.clear_by_ip_strikes()
    ratelimit_handler._by_ip_autoban_counts["2001:db8:0:1::/64"] = (
        _WindowedCategoryCounts()
    )
    ratelimit_handler._by_ip_autoban_counts["2001:db9:0:1::/64"] = (
        _WindowedCategoryCounts()
    )

    await IPBanManager().forget_strikes_inside(["2001:db8::/32", "198.51.100.0/24"])

    assert sorted(middleware.suspicious_request_counts) == [
        "2001:db9:0:1::/64",
        "203.0.113.10",
    ]
    assert list(ratelimit_handler._by_ip_autoban_counts) == ["2001:db9:0:1::/64"]
    ratelimit_handler.clear_by_ip_strikes()
