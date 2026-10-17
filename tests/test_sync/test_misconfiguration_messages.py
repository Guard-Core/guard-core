import warnings
from collections.abc import Callable
from typing import Any

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.decorators import SecurityDecorator

NOT_SET = (
    "fail_on_misconfiguration is not set. guard-core 5.0.0 will refuse to start "
    "with this misconfiguration. Pass fail_on_misconfiguration=True to "
    "SecurityConfig now to opt in, or fail_on_misconfiguration=False to keep "
    "starting with it."
)
FALSE_NOTE = (
    "fail_on_misconfiguration=False keeps starting with it. guard-core 5.0.0 "
    "will refuse to start with this misconfiguration unless that setting is False."
)
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
]


@pytest.mark.parametrize(("settings", "problem"), CONFIG_PROBLEMS)
def test_config_misconfiguration_text_and_location(
    settings: dict[str, Any], problem: str, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level("WARNING"), pytest.warns(DeprecationWarning):
        SecurityConfig(enable_redis=False, **settings)
    assert [r.name for r in caplog.records if problem in r.getMessage()] == [
        "guard_core.models"
    ]

    for flag, note in (
        ({}, NOT_SET),
        ({"fail_on_misconfiguration": False}, FALSE_NOTE),
    ):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            SecurityConfig(enable_redis=False, **settings, **flag)

        matching = [w for w in caught if problem in str(w.message)]
        assert len(matching) == 1
        assert str(matching[0].message) == f"{problem} {note}"
        assert matching[0].category is DeprecationWarning
        assert matching[0].filename == __file__

    with pytest.raises(ValueError) as error:
        SecurityConfig(enable_redis=False, fail_on_misconfiguration=True, **settings)
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
    make: Callable[[SecurityDecorator], Any], problem: str
) -> None:
    decorator = SecurityDecorator(SecurityConfig(enable_redis=False))

    def route() -> None:
        pass

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        make(decorator)(route)

    assert len(caught) == 1
    assert str(caught[0].message) == f"{problem} {NOT_SET}"
    assert caught[0].filename == __file__

    strict = SecurityDecorator(
        SecurityConfig(enable_redis=False, fail_on_misconfiguration=True)
    )
    with pytest.raises(ValueError) as error:
        make(strict)(route)
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
    make: Callable[[SecurityDecorator], Any], decorator_text: str
) -> None:
    config = SecurityConfig(enable_redis=False)
    decorator = SecurityDecorator(config)

    def country_route() -> None:
        pass

    decorated = make(decorator)(country_route)
    initializer = HandlerInitializer(config, guard_decorator=decorator)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        initializer.initialize_redis_handlers()

    problem = (
        f"Route {decorated._guard_route_id!r} uses {decorator_text} but no GeoIP "
        "database is configured (geo_ip_handler is None; set ipinfo_token or "
        "geo_ip_handler), so the country rule is ignored."
    )
    assert len(caught) == 1
    assert str(caught[0].message) == f"{problem} {NOT_SET}"
    assert caught[0].filename == __file__


def test_startup_report_text_and_location_for_an_unreachable_ban_threshold() -> None:
    config = SecurityConfig(
        enable_redis=False, enable_penetration_detection=False, auto_ban_threshold=10001
    )

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        HandlerInitializer(config).initialize_redis_handlers()

    problem = (
        "auto_ban_threshold is 10001, above the 10,000 events retained per "
        "category, so this ban threshold can never fire. Lower it to at most 10,000."
    )
    assert len(caught) == 1
    assert str(caught[0].message) == f"{problem} {NOT_SET}"
    assert caught[0].filename == __file__
