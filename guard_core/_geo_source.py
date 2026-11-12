from guard_core._config_capabilities import _extra_installed, install_hint
from guard_core._misconfiguration_kinds import (
    K_COUNTRY_RULE_GEOIP_DOWNLOAD_EXTRAS_MISSING,
    K_COUNTRY_RULE_NO_GEOIP_SOURCE,
    Problem,
)


def lacks_geo_source(geo_ip_handler: object, ipinfo_token: str | None) -> bool:
    return geo_ip_handler is None and not ipinfo_token


def missing_geo_download_extras(downloader: str) -> list[str]:
    return [name for name in ("maxminddb", downloader) if not _extra_installed(name)]


def geo_source_problem(
    rule: str,
    geo_ip_handler: object,
    ipinfo_token: str | None,
    downloader: str,
    adapter: str | None = None,
) -> Problem | None:
    if lacks_geo_source(geo_ip_handler, ipinfo_token):
        return Problem(
            f"{rule} declares a country rule but no GeoIP database is configured "
            "(geo_ip_handler is None and ipinfo_token is not set; set "
            "ipinfo_token or geo_ip_handler), so the country rule would be "
            "ignored.",
            kind=K_COUNTRY_RULE_NO_GEOIP_SOURCE,
            subject=rule,
        )
    missing = missing_geo_download_extras(downloader)
    if geo_ip_handler is None and missing:
        return Problem(
            f"{rule} declares a country rule and ipinfo_token is set, but the "
            f"GeoIP database download needs {' and '.join(repr(m) for m in missing)} "
            f"which is not installed. Install it with: {install_hint('geo', adapter)}",
            kind=K_COUNTRY_RULE_GEOIP_DOWNLOAD_EXTRAS_MISSING,
            subject=rule,
        )
    return None
