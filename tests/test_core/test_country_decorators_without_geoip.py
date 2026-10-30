import logging
import warnings
from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.decorators import SecurityDecorator
from guard_core.models import SecurityConfig


def _decorated(
    make: Callable[[SecurityDecorator], Any], **flag: bool
) -> tuple[SecurityConfig, SecurityDecorator, str]:
    config = SecurityConfig(enable_redis=False, **flag)
    decorator = SecurityDecorator(
        SecurityConfig(enable_redis=False, geo_ip_handler=MagicMock(), **flag)
    )

    def country_route() -> None:
        pass

    decorated = make(decorator)(country_route)
    return config, decorator, decorated._guard_route_id


COUNTRY_DECORATORS: list[Callable[[SecurityDecorator], Any]] = [
    lambda d: d.block_countries(["CN"]),
    lambda d: d.allow_countries(["US"]),
    lambda d: d.geo_rate_limit({"US": (5, 60), "*": (50, 60)}),
]


@pytest.mark.parametrize("make", COUNTRY_DECORATORS)
class TestCountryDecoratorWithoutGeoIp:
    async def test_unset_flag_refuses_naming_the_route(
        self, make: Callable[[SecurityDecorator], Any]
    ) -> None:
        config, decorator, route_id = _decorated(make)
        initializer = HandlerInitializer(config, guard_decorator=decorator)

        with pytest.raises(ValueError) as caught:
            await initializer.initialize_redis_handlers()

        message = str(caught.value)
        assert route_id in message
        assert "no GeoIP database" in message
        assert "fail_on_misconfiguration=False" in message

    async def test_true_raises_at_startup(
        self, make: Callable[[SecurityDecorator], Any]
    ) -> None:
        config, decorator, route_id = _decorated(make, fail_on_misconfiguration=True)
        initializer = HandlerInitializer(config, guard_decorator=decorator)

        with pytest.raises(ValueError, match="no GeoIP database"):
            await initializer.initialize_redis_handlers()

    async def test_false_logs_one_warning_and_starts(
        self,
        make: Callable[[SecurityDecorator], Any],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        config, decorator, _ = _decorated(make, fail_on_misconfiguration=False)
        initializer = HandlerInitializer(config, guard_decorator=decorator)

        with caplog.at_level(logging.WARNING, logger="guard_core"):
            with warnings.catch_warnings():
                warnings.simplefilter("error")
                await initializer.initialize_redis_handlers()

        messages = [r.getMessage() for r in caplog.records if "GeoIP" in r.message]
        assert len(messages) == 1
        assert "keeps starting" in messages[0]

    async def test_a_geoip_handler_means_no_report(
        self, make: Callable[[SecurityDecorator], Any]
    ) -> None:
        geo = MagicMock()

        async def initialize() -> None:
            return None

        geo.initialize = initialize
        config, decorator, _ = _decorated(make, fail_on_misconfiguration=True)
        config.geo_ip_handler = geo
        initializer = HandlerInitializer(
            config, guard_decorator=decorator, geo_ip_handler=geo
        )

        with warnings.catch_warnings():
            warnings.simplefilter("error")
            await initializer.initialize_redis_handlers()


async def test_a_mixed_pair_with_the_decorator_opted_out_starts_and_warns_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    middleware_config = SecurityConfig(
        enable_redis=False, fail_on_misconfiguration=True
    )
    decorator = SecurityDecorator(
        SecurityConfig(enable_redis=False, fail_on_misconfiguration=False)
    )
    decorator.block_countries(["CN"])(lambda: None)
    initializer = HandlerInitializer(middleware_config, guard_decorator=decorator)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        await initializer.initialize_redis_handlers()
        await initializer.initialize_redis_handlers()

    assert caplog.text.count("no GeoIP database") == 1


def test_the_reverse_mixed_pair_still_raises_at_declaration() -> None:
    decorator = SecurityDecorator(
        SecurityConfig(enable_redis=False, fail_on_misconfiguration=True)
    )
    HandlerInitializer(
        SecurityConfig(enable_redis=False, fail_on_misconfiguration=False),
        guard_decorator=decorator,
    )

    with pytest.raises(ValueError, match="no GeoIP database is configured"):
        decorator.block_countries(["CN"])(lambda: None)


async def test_other_decorators_and_no_decorator_never_report() -> None:
    config, decorator, _ = _decorated(
        lambda d: d.rate_limit(5, 60), fail_on_misconfiguration=True
    )

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        await HandlerInitializer(
            config, guard_decorator=decorator
        ).initialize_redis_handlers()
        await HandlerInitializer(config).initialize_redis_handlers()


async def test_the_report_names_the_decorator_in_use(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config, decorator, _ = _decorated(
        lambda d: d.geo_rate_limit({"*": (5, 60)}), fail_on_misconfiguration=False
    )

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        await HandlerInitializer(
            config, guard_decorator=decorator
        ).initialize_redis_handlers()

    assert "geo_rate_limit" in caplog.text
    assert "block_countries" not in caplog.text


@pytest.mark.parametrize("make", COUNTRY_DECORATORS)
class TestCountryRuleDeclaration:
    def test_true_raises_at_declaration(
        self, make: Callable[[SecurityDecorator], Any]
    ) -> None:
        decorator = SecurityDecorator(SecurityConfig(enable_redis=False))

        with pytest.raises(ValueError, match="no GeoIP database is configured"):
            make(decorator)(lambda: None)

    def test_false_does_nothing_at_declaration(
        self,
        make: Callable[[SecurityDecorator], Any],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        decorator = SecurityDecorator(
            SecurityConfig(enable_redis=False, fail_on_misconfiguration=False)
        )

        with caplog.at_level(logging.WARNING, logger="guard_core"):
            make(decorator)(lambda: None)

        assert "GeoIP" not in caplog.text

    def test_a_geo_handler_means_no_error(
        self, make: Callable[[SecurityDecorator], Any]
    ) -> None:
        decorator = SecurityDecorator(
            SecurityConfig(enable_redis=False, geo_ip_handler=MagicMock())
        )

        make(decorator)(lambda: None)

    def test_a_token_with_the_extras_means_no_error(
        self, make: Callable[[SecurityDecorator], Any]
    ) -> None:
        decorator = SecurityDecorator(
            SecurityConfig(enable_redis=False, ipinfo_token="t")
        )

        make(decorator)(lambda: None)

    def test_a_token_without_the_downloader_raises_at_declaration(
        self,
        make: Callable[[SecurityDecorator], Any],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "guard_core._geo_source._extra_installed", lambda name: False
        )
        decorator = SecurityDecorator(
            SecurityConfig(enable_redis=False, ipinfo_token="t")
        )

        with pytest.raises(ValueError, match="'maxminddb' and '(aiohttp|requests)'"):
            make(decorator)(lambda: None)

    def test_the_two_config_case_raises_at_declaration(
        self, make: Callable[[SecurityDecorator], Any]
    ) -> None:
        middleware_config = SecurityConfig(enable_redis=False, ipinfo_token="t")
        decorator = SecurityDecorator(SecurityConfig(enable_redis=False))

        assert middleware_config.ipinfo_token == "t"
        with pytest.raises(ValueError, match="no GeoIP database is configured"):
            make(decorator)(lambda: None)


def test_empty_country_rules_declare_no_geo_requirement() -> None:
    strict = SecurityDecorator(
        SecurityConfig(enable_redis=False, fail_on_misconfiguration=False)
    )

    strict.block_countries([])(lambda: None)
    strict.geo_rate_limit({})(lambda: None)


async def test_the_route_report_is_emitted_once_across_two_calls(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config, decorator, _ = _decorated(
        lambda d: d.block_countries(["CN"]), fail_on_misconfiguration=False
    )
    initializer = HandlerInitializer(config, guard_decorator=decorator)

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        initializer.report_route_misconfigurations()
        initializer.report_route_misconfigurations()
        await initializer.initialize_redis_handlers()

    assert caplog.text.count("no GeoIP database") == 1
