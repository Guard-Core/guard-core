from tests.live_smoke.scenarios.rate_limit_and_bans import _build_single_entry_mmdb

CLIENT_IP = "203.0.113.5"


def country_database_bytes(country: str, ip: str = CLIENT_IP) -> bytes:
    return _build_single_entry_mmdb(ip, country)
