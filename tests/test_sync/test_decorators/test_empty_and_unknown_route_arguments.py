import logging
import warnings
from collections.abc import Callable
from typing import Any

import pytest

from guard_core.models import VALID_CLOUD_PROVIDERS, SyncSecurityConfig
from guard_core.sync.decorators import SecurityDecorator


def _decorator(**flag: bool) -> SecurityDecorator:
    return SecurityDecorator(
        SyncSecurityConfig(enable_redis=False, ipinfo_token="test-token", **flag)
    )


def _decorate(
    decorator: SecurityDecorator, make: Callable[[SecurityDecorator], Any]
) -> Any:
    def route() -> None:
        pass

    return make(decorator)(route)


EMPTY_LISTS: list[tuple[str, Callable[[SecurityDecorator], Any], str]] = [
    (
        "require_ip",
        lambda d: d.require_ip(whitelist=[]),
        "@require_ip received an empty whitelist",
    ),
    (
        "allow_countries",
        lambda d: d.allow_countries([]),
        "@allow_countries received an empty country list",
    ),
]


@pytest.mark.parametrize(("name", "make", "problem"), EMPTY_LISTS)
class TestEmptyAllowList:
    def test_unset_flag_refuses_naming_the_problem_and_the_old_value(
        self, name: str, make: Callable[[SecurityDecorator], Any], problem: str
    ) -> None:
        with pytest.raises(ValueError) as caught:
            _decorate(_decorator(), make)

        message = str(caught.value)
        assert problem in message
        assert "fail_on_misconfiguration=False" in message

    def test_true_raises_before_the_route_config_is_touched(
        self, name: str, make: Callable[[SecurityDecorator], Any], problem: str
    ) -> None:
        decorator = _decorator(fail_on_misconfiguration=True)

        with pytest.raises(ValueError, match="empty"):
            _decorate(decorator, make)

        assert decorator._route_configs == {}

    def test_false_logs_one_warning_and_starts(
        self,
        name: str,
        make: Callable[[SecurityDecorator], Any],
        problem: str,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="guard_core"):
            with warnings.catch_warnings():
                warnings.simplefilter("error")
                _decorate(_decorator(fail_on_misconfiguration=False), make)

        messages = [r.getMessage() for r in caplog.records if problem in r.message]
        assert len(messages) == 1
        assert "keeps starting" in messages[0]


def test_empty_whitelist_still_applies_no_restriction_when_only_warned() -> None:
    decorator = _decorator(fail_on_misconfiguration=False)

    route = _decorate(decorator, lambda d: d.require_ip(whitelist=[]))

    route_config = decorator.get_route_config(route._guard_route_id)
    assert route_config is not None
    assert not route_config.ip_whitelist


@pytest.mark.parametrize(
    "make",
    [
        lambda d: d.require_ip(),
        lambda d: d.require_ip(blacklist=[]),
        lambda d: d.require_ip(whitelist=["203.0.113.7"]),
        lambda d: d.allow_countries(["US"]),
        lambda d: d.block_countries([]),
    ],
)
def test_a_non_empty_or_unrelated_argument_never_warns(
    make: Callable[[SecurityDecorator], Any],
) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _decorate(_decorator(fail_on_misconfiguration=True), make)


class TestUnknownCloudProvider:
    def test_unset_flag_refuses_naming_the_unknown_provider(self) -> None:
        with pytest.raises(ValueError) as caught:
            _decorate(_decorator(), lambda d: d.block_clouds(["AWS", "Bogus"]))

        message = str(caught.value)
        assert "ignored unknown cloud providers ['Bogus']" in message
        assert "fail_on_misconfiguration=False" in message

    def test_false_filters_the_unknown_provider_and_logs_it(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        decorator = _decorator(fail_on_misconfiguration=False)

        with caplog.at_level(logging.WARNING, logger="guard_core"):
            route = _decorate(decorator, lambda d: d.block_clouds(["AWS", "Bogus"]))

        assert "ignored unknown cloud providers ['Bogus']" in caplog.text
        route_config = decorator.get_route_config(route._guard_route_id)
        assert route_config is not None
        assert route_config.block_cloud_providers == {"AWS"}

    def test_true_raises_without_creating_the_route_config(self) -> None:
        decorator = _decorator(fail_on_misconfiguration=True)

        with pytest.raises(ValueError, match="unknown cloud providers"):
            _decorate(decorator, lambda d: d.block_clouds(["Bogus"]))

        assert decorator._route_configs == {}

    def test_every_provider_unknown_is_reported(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        decorator = _decorator(fail_on_misconfiguration=False)

        with caplog.at_level(logging.WARNING, logger="guard_core"):
            _decorate(decorator, lambda d: d.block_clouds(["aws-typo"]))

        assert "'aws-typo'" in caplog.text

    @pytest.mark.parametrize(
        ("given", "stored"),
        [
            (["aws"], {"AWS"}),
            (["AZURE", "gcp"], {"Azure", "GCP"}),
            (["digitalocean:!nyc1"], {"DigitalOcean:!nyc1"}),
        ],
    )
    def test_case_variants_are_canonical_not_unknown(
        self, given: list[str], stored: set[str]
    ) -> None:
        decorator = _decorator(fail_on_misconfiguration=True)

        with warnings.catch_warnings():
            warnings.simplefilter("error")
            route = _decorate(decorator, lambda d: d.block_clouds(given))

        route_config = decorator.get_route_config(route._guard_route_id)
        assert route_config is not None
        assert route_config.block_cloud_providers == stored

    def test_default_and_valid_names_never_warn(self) -> None:
        decorator = _decorator(fail_on_misconfiguration=True)

        with warnings.catch_warnings():
            warnings.simplefilter("error")
            route = _decorate(decorator, lambda d: d.block_clouds())

        route_config = decorator.get_route_config(route._guard_route_id)
        assert route_config is not None
        assert route_config.block_cloud_providers == set(VALID_CLOUD_PROVIDERS)
