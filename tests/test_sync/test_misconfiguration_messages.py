import inspect
import logging
import re
import warnings
from collections.abc import Callable
from typing import Any

import pytest

from guard_core import _misconfiguration, models
from guard_core._emergency_exemptions import warn_unexempted_probe_paths
from guard_core._security_config_fields import DEFAULT_EXCLUDE_PATHS
from guard_core.models import SecurityConfig, SyncSecurityConfig
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.core.validation.path_matching import (
    _has_routing_anomaly_in_any_decoding,
)
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
        {
            "enable_cors": True,
            "cors_allow_origins": ["*"],
            "cors_allow_credentials": True,
        },
        "CORS misconfiguration: wildcard origin '*' is incompatible with "
        "cors_allow_credentials=True.",
    ),
    (
        {"endpoint_rate_limits": {"/a//b": (5, 60)}},
        "endpoint_rate_limits key '/a//b' has a dot segment, an empty segment, a "
        "backslash or an encoded dot or separator (in any decoding round), a "
        "spelling the router does not serve as written. Write the plain path.",
    ),
]

for _template_key in (
    "/users/{id}",
    "/files/{path:path}",
    "/users/<id>",
    "/users/<int:id>",
    "/users/(?P<id>[0-9]+)",
    "/users/([0-9]+)",
    "/users/(.*)",
    "/users/(.+)",
    "^/users/([0-9]+)$",
    "/files/[0-9]+",
):
    CONFIG_PROBLEMS.append(
        (
            {"endpoint_rate_limits": {_template_key: (5, 60)}},
            f"endpoint_rate_limits key {_template_key!r} is a router template or "
            "a regex route ({name}, <name>, (?P<name>...), ([0-9]+) or "
            "[0-9]+): it matches only that literal text, so it limits nothing. "
            "Write a concrete path, or put the limit on the route with the "
            "rate_limit decorator.",
        )
    )


def test_a_backslash_group_key_reports_the_regex_route_line_too(
    caplog: pytest.LogCaptureFixture,
) -> None:
    key = "/users/(\\d+)"
    with caplog.at_level("WARNING"):
        SyncSecurityConfig(
            enable_redis=False,
            fail_on_misconfiguration=False,
            endpoint_rate_limits={key: (5, 60)},
        )
    messages = [r.getMessage() for r in caplog.records]
    assert any("is a router template or a regex route" in m for m in messages)
    assert any(
        "has a dot segment, an empty segment, a backslash" in m for m in messages
    )


@pytest.mark.parametrize(("settings", "problem"), CONFIG_PROBLEMS)
def test_config_misconfiguration_text_and_location(
    settings: dict[str, Any], problem: str, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level("WARNING"), warnings.catch_warnings():
        warnings.simplefilter("error")
        SyncSecurityConfig(
            enable_redis=False, fail_on_misconfiguration=False, **settings
        )
    assert [
        (r.name, r.getMessage()) for r in caplog.records if problem in r.getMessage()
    ] == [("guard_core.models", f"{problem} {FALSE_NOTE}")]

    for flag in ({}, {"fail_on_misconfiguration": True}):
        with pytest.raises(ValueError) as error:
            SyncSecurityConfig(enable_redis=False, **settings, **flag)
        assert f"{problem} {TRUE_NOTE}" in str(error.value)


def test_semantic_and_threat_thresholds_at_a_small_positive_value_do_not_warn() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        SyncSecurityConfig(
            enable_redis=False,
            fail_on_misconfiguration=True,
            detection_threat_score_threshold=0.01,
            detection_semantic_threshold=0.01,
        )


def test_endpoint_rate_limits_at_one_never_warn() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        SyncSecurityConfig(
            enable_redis=False,
            fail_on_misconfiguration=True,
            endpoint_rate_limits={"/a": (1, 60), "/b": (5, 1)},
        )


@pytest.mark.parametrize(
    "key",
    [
        "/users/1",
        "/a-b_c.d",
        "/a{b",
        "/a}b{",
        "/a<b",
        "/wiki/Foo_(bar)",
        "/c++",
        "/a$",
    ],
)
def test_a_concrete_endpoint_key_never_warns(key: str) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        SyncSecurityConfig(
            enable_redis=False,
            fail_on_misconfiguration=True,
            endpoint_rate_limits={key: (5, 60)},
        )


def test_a_path_that_merely_contains_the_letter_x_is_not_a_glob() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        SyncSecurityConfig(
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
        SyncSecurityConfig(enable_redis=False, fail_on_misconfiguration=False)
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
        SyncSecurityConfig(enable_redis=False),
        SyncSecurityConfig(enable_redis=False, fail_on_misconfiguration=True),
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
    config = SyncSecurityConfig(enable_redis=False, fail_on_misconfiguration=False)
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
    config = SyncSecurityConfig(
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


def test_no_default_exclude_path_has_a_routing_anomaly() -> None:
    """The misconfiguration check skips the defaults, so none may be flagged."""
    assert [
        entry
        for entry in DEFAULT_EXCLUDE_PATHS
        if _has_routing_anomaly_in_any_decoding(entry)
    ] == []


def test_the_checked_fields_name_every_field_a_check_reads() -> None:
    source = inspect.getsource(_misconfiguration)
    read = set(re.findall(r"config\.([a-z_]+)", source))
    read |= set(re.findall(r'"(detection_[a-z_]+_threshold)"', source))
    read -= {"fail_on_misconfiguration", "emergency_mode"}
    read -= {"model_fields_set", "__pydantic_fields_set__"}
    read -= {"emergency_exempt_paths"}

    assert read <= _misconfiguration.CHECKED_FIELDS
    assert _misconfiguration.CHECKED_FIELDS <= set(SecurityConfig.model_fields)


def test_a_config_that_states_no_checked_field_has_no_problem_to_report() -> None:
    assert _misconfiguration.config_misconfigurations(SyncSecurityConfig()) == []
    assert _misconfiguration.config_misconfigurations(
        SyncSecurityConfig(rate_limit=0, fail_on_misconfiguration=False)
    ) == ["rate_limit is 0: a limit below 1 blocks every request."]


def test_a_check_whose_fields_are_all_unset_does_not_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "_unknown_security_headers_key_problems",
        "_glob_exclude_path_problems",
        "_anomalous_path_problems",
        "_zero_detection_threshold_problems",
        "wildcard_cors_credentials_problems",
    ):

        def refuse(_config: object) -> list[str]:
            raise AssertionError("a check ran on defaults only")

        monkeypatch.setattr(_misconfiguration, name, refuse)

    config = SyncSecurityConfig(rate_limit=0, fail_on_misconfiguration=False)

    assert _misconfiguration.config_misconfigurations(config) == [
        "rate_limit is 0: a limit below 1 blocks every request."
    ]


def test_every_stated_surface_still_reports_its_problem() -> None:
    config = SyncSecurityConfig(
        security_headers={"enabled": True, "no_such_key": 1},
        exclude_paths=["/a/*"],
        endpoint_rate_limits={"/x": (0, 0)},
        detection_threat_score_threshold=0.0,
        fail_on_misconfiguration=False,
    )

    problems = _misconfiguration.config_misconfigurations(config)

    assert [re.split(r"[ \[]", problem)[0] for problem in problems] == [
        "security_headers",
        "exclude_paths",
        "endpoint_rate_limits",
        "detection_threat_score_threshold",
    ]


def test_the_fields_of_each_check_make_up_the_checked_fields() -> None:
    assert _misconfiguration.CHECKED_FIELDS == (
        _misconfiguration._HEADER_FIELDS
        | _misconfiguration._PATH_FIELDS
        | _misconfiguration._RATE_LIMIT_FIELDS
        | _misconfiguration._THRESHOLD_FIELDS
        | _misconfiguration._CORS_FIELDS
    )


def test_the_probe_path_warning_is_given_in_emergency_mode_only(
    caplog: pytest.LogCaptureFixture,
) -> None:
    quiet = SyncSecurityConfig(exclude_paths=["/health"])
    loud = SyncSecurityConfig(exclude_paths=["/health"], emergency_mode=True)
    logger = logging.getLogger("probe_paths")
    caplog.clear()

    with caplog.at_level("WARNING", logger="probe_paths"):
        warn_unexempted_probe_paths(quiet, logger)
        assert caplog.records == []
        warn_unexempted_probe_paths(loud, logger)

    assert [r.name for r in caplog.records] == ["probe_paths"]
    assert "[EMERGENCY MODE]" in caplog.records[0].getMessage()


def _count_reports(monkeypatch: pytest.MonkeyPatch) -> list[SecurityConfig[Any]]:
    reported: list[SecurityConfig[Any]] = []
    real = models.report_config_misconfigurations

    def spy(config: SecurityConfig[Any], *, stacklevel: int) -> None:
        reported.append(config)
        real(config, stacklevel=stacklevel)

    monkeypatch.setattr(models, "report_config_misconfigurations", spy)
    return reported


def test_a_valid_rate_limit_alone_does_not_start_the_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reported = _count_reports(monkeypatch)

    SyncSecurityConfig(rate_limit=120, enable_redis=False)

    assert reported == []


@pytest.mark.parametrize(
    "stated",
    [
        {"rate_limit": 0, "fail_on_misconfiguration": False},
        {"emergency_mode": True},
        {"security_headers": {"enabled": True}},
        {"exclude_paths": ["/health"]},
        {"endpoint_rate_limits": {"/x": (5, 60)}},
        {"rate_limit_window": 60},
        {"detection_threat_score_threshold": 0.5},
        {"detection_semantic_threshold": 0.5},
        {"enable_cors": True},
        {"cors_allow_origins": ["https://a.example"]},
        {"cors_allow_credentials": True},
    ],
)
def test_every_other_stated_checked_field_still_starts_the_report(
    monkeypatch: pytest.MonkeyPatch, stated: dict[str, Any]
) -> None:
    reported = _count_reports(monkeypatch)

    SyncSecurityConfig(enable_redis=False, **stated)

    assert len(reported) == 1


def test_the_fields_checked_beside_rate_limit_are_the_checked_fields_but_it() -> None:
    assert _misconfiguration.CHECKED_FIELDS_BESIDES_RATE_LIMIT == (
        _misconfiguration.CHECKED_FIELDS - {"rate_limit"}
    )
