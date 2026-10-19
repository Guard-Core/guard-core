import warnings
from collections.abc import Callable
from typing import Any

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.decorators import SecurityDecorator

FALSE_NOTE = "fail_on_misconfiguration=False keeps starting with it."
TRUE_NOTE = "Set fail_on_misconfiguration=False to start with it anyway."

CONFIG_PROBLEMS: list[tuple[dict[str, Any], str]] = [
    (
        {"rate_limit": 0},
        "rate_limit is 0: a limit below 1 blocks every request.",
    ),
    (
        {"rate_limit_window": 0},
        "rate_limit_window is 0: a window below 1 second disables the rate limiter.",
    ),
    (
        {"endpoint_rate_limits": {"/login": (0, 60)}},
        "endpoint_rate_limits['/login'] is (0, 60): the limit and the window must "
        "both be at least 1.",
    ),
    (
        {"detection_threat_score_threshold": 0.0},
        "detection_threat_score_threshold is 0.0: every request would be flagged "
        "as a threat.",
    ),
    (
        {"detection_semantic_threshold": 0.0},
        "detection_semantic_threshold is 0.0: every request would be flagged as a "
        "threat.",
    ),
    (
        {"exclude_paths": ["/static/*"]},
        "exclude_paths entry '/static/*' is not a glob: wildcards are literal "
        "characters, so it excludes nothing.",
    ),
    (
        {"exclude_paths": ["/a/../b"]},
        "exclude_paths entry '/a/../b' has a dot segment, an empty segment, a "
        "backslash or an encoded dot or separator (in any decoding round), a "
        "spelling the router does not serve as written. Write the plain path.",
    ),
    (
        {"endpoint_rate_limits": {"/a//b": (5, 60)}},
        "endpoint_rate_limits key '/a//b' has a dot segment, an empty segment, a "
        "backslash or an encoded dot or separator (in any decoding round), a "
        "spelling the router does not serve as written. Write the plain path.",
    ),
]


@pytest.mark.parametrize(("settings", "problem"), CONFIG_PROBLEMS)
def test_config_misconfiguration_text_and_location(
    settings: dict[str, Any], problem: str, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level("WARNING"), warnings.catch_warnings():
        warnings.simplefilter("error")
        SecurityConfig(enable_redis=False, fail_on_misconfiguration=False, **settings)
    assert [
        (r.name, r.getMessage()) for r in caplog.records if problem in r.getMessage()
    ] == [("guard_core.models", f"{problem} {FALSE_NOTE}")]

    for flag in ({}, {"fail_on_misconfiguration": True}):
        with pytest.raises(ValueError) as error:
            SecurityConfig(enable_redis=False, **settings, **flag)
        assert f"{problem} {TRUE_NOTE}" in str(error.value)


def test_semantic_and_threat_thresholds_at_a_small_positive_value_do_not_warn() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        SecurityConfig(
            enable_redis=False,
            fail_on_misconfiguration=True,
            detection_threat_score_threshold=0.01,
            detection_semantic_threshold=0.01,
        )


def test_endpoint_rate_limits_at_one_never_warn() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        SecurityConfig(
            enable_redis=False,
            fail_on_misconfiguration=True,
            endpoint_rate_limits={"/a": (1, 60), "/b": (5, 1)},
        )


def test_a_path_that_merely_contains_the_letter_x_is_not_a_glob() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        SecurityConfig(
            enable_redis=False,
            fail_on_misconfiguration=True,
            exclude_paths=["/XMAX", "/status"],
        )


DECORATOR_PROBLEMS: list[tuple[Callable[[SecurityDecorator], Any], str]] = [
    (
        lambda d: d.require_ip(whitelist=[]),
        "@require_ip received an empty whitelist: an empty list restricts nothing, "
        "so every address is allowed on this route.",
    ),
    (
        lambda d: d.require_ip(blacklist=["10.0.0.0/33"]),
        "@require_ip blacklist entry '10.0.0.0/33' is not a valid IP address or "
        "CIDR network, so requests to this route can be denied by mistake.",
    ),
    (
        lambda d: d.allow_countries([]),
        "@allow_countries received an empty country list: an empty list restricts "
        "nothing, so every country is allowed on this route.",
    ),
    (
        lambda d: d.block_clouds(["Bogus"]),
        "@block_clouds: ignored unknown cloud providers ['Bogus']. Valid providers: "
        "['AWS', 'Azure', 'DigitalOcean', 'GCP', 'Linode', 'Vultr'] (matched "
        "case-insensitively).",
    ),
    (
        lambda d: d.rate_limit(0, 60),
        "@rate_limit(requests=0, window=60): the limit and the window must both be "
        "at least 1.",
    ),
    (
        lambda d: d.geo_rate_limit({"US": (0, 60)}),
        "@geo_rate_limit entry 'US' is (0, 60): the limit and the window must both "
        "be at least 1.",
    ),
    (
        lambda d: d.time_window("25:00", "17:00"),
        "@time_window start_time '25:00' is not a valid HH:MM time, so the window "
        "is evaluated on a broken value.",
    ),
    (
        lambda d: d.time_window("09:00", "later"),
        "@time_window end_time 'later' is not a valid HH:MM time, so the window is "
        "evaluated on a broken value.",
    ),
    (
        lambda d: d.time_window("09:00", "17:00", "Mars/Olympus"),
        "@time_window timezone 'Mars/Olympus' is not a known IANA time zone, so "
        "the window silently falls back to UTC.",
    ),
]


@pytest.mark.parametrize(("make", "problem"), DECORATOR_PROBLEMS)
def test_decorator_misconfiguration_text_and_location(
    make: Callable[[SecurityDecorator], Any],
    problem: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    lenient = SecurityDecorator(
        SecurityConfig(enable_redis=False, fail_on_misconfiguration=False)
    )

    def route() -> None:
        pass

    with caplog.at_level("WARNING"), warnings.catch_warnings():
        warnings.simplefilter("error")
        make(lenient)(route)

    assert [
        (r.name, r.getMessage()) for r in caplog.records if problem in r.getMessage()
    ] == [("guard_core.sync.decorators", f"{problem} {FALSE_NOTE}")]

    for config in (
        SecurityConfig(enable_redis=False),
        SecurityConfig(enable_redis=False, fail_on_misconfiguration=True),
    ):
        with pytest.raises(ValueError) as error:
            make(SecurityDecorator(config))(route)
        assert str(error.value) == f"{problem} {TRUE_NOTE}"


@pytest.mark.parametrize(
    ("make", "decorator_text"),
    [
        (lambda d: d.block_countries(["CN"]), "block_countries or allow_countries"),
        (lambda d: d.allow_countries(["US"]), "block_countries or allow_countries"),
        (lambda d: d.geo_rate_limit({"*": (5, 60)}), "geo_rate_limit"),
    ],
)
def test_startup_report_text_and_location_for_country_decorators(
    make: Callable[[SecurityDecorator], Any],
    decorator_text: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(enable_redis=False, fail_on_misconfiguration=False)
    decorator = SecurityDecorator(config)

    def country_route() -> None:
        pass

    decorated = make(decorator)(country_route)
    initializer = HandlerInitializer(config, guard_decorator=decorator)

    with caplog.at_level("WARNING"), warnings.catch_warnings():
        warnings.simplefilter("error")
        initializer.initialize_redis_handlers()

    problem = (
        f"Route {decorated._guard_route_id!r} uses {decorator_text} but no GeoIP "
        "database is configured (geo_ip_handler is None; set ipinfo_token or "
        "geo_ip_handler), so the country rule is ignored."
    )
    assert [
        (r.name, r.getMessage()) for r in caplog.records if problem in r.getMessage()
    ] == [("guard_core.sync.core.initialization", f"{problem} {FALSE_NOTE}")]


def test_startup_report_text_and_location_for_an_unreachable_ban_threshold(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        rate_limit=10,
        rate_limit_window=60,
        auto_ban_threshold=10001,
        fail_on_misconfiguration=False,
    )

    with caplog.at_level("WARNING"), warnings.catch_warnings():
        warnings.simplefilter("error")
        HandlerInitializer(config).initialize_redis_handlers()

    problem = (
        "auto_ban_threshold is 10001, above the 610 strikes one client can "
        "produce in 3600 s with rate_limit=10 per 60 s (rate_limit x (3600 / "
        "rate_limit_window + 1)), so this ban threshold can never fire. Lower it "
        "to at most 610 or raise rate_limit."
    )
    assert [
        (r.name, r.getMessage()) for r in caplog.records if problem in r.getMessage()
    ] == [("guard_core.sync.core.initialization", f"{problem} {FALSE_NOTE}")]
