import logging
import warnings
from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.decorators import SecurityDecorator


def _decorated(
    make: Callable[[SecurityDecorator], Any], **flag: bool
) -> tuple[SyncSecurityConfig, SecurityDecorator, str]:
    config = SyncSecurityConfig(enable_redis=False, **flag)
    decorator = SecurityDecorator(config)

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
    def test_unset_flag_refuses_naming_the_route(
        self, make: Callable[[SecurityDecorator], Any]
    ) -> None:
        config, decorator, route_id = _decorated(make)
        initializer = HandlerInitializer(config, guard_decorator=decorator)

        with pytest.raises(ValueError) as caught:
            initializer.initialize_redis_handlers()

        message = str(caught.value)
        assert route_id in message
        assert "no GeoIP database" in message
        assert "fail_on_misconfiguration=False" in message

    def test_true_raises_at_startup(
        self, make: Callable[[SecurityDecorator], Any]
    ) -> None:
        config, decorator, route_id = _decorated(make, fail_on_misconfiguration=True)
        initializer = HandlerInitializer(config, guard_decorator=decorator)

        with pytest.raises(ValueError, match="no GeoIP database"):
            initializer.initialize_redis_handlers()

    def test_false_logs_one_warning_and_starts(
        self,
        make: Callable[[SecurityDecorator], Any],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        config, decorator, _ = _decorated(make, fail_on_misconfiguration=False)
        initializer = HandlerInitializer(config, guard_decorator=decorator)

        with caplog.at_level(logging.WARNING, logger="guard_core"):
            with warnings.catch_warnings():
                warnings.simplefilter("error")
                initializer.initialize_redis_handlers()

        messages = [r.getMessage() for r in caplog.records if "GeoIP" in r.message]
        assert len(messages) == 1
        assert "keeps starting" in messages[0]

    def test_a_geoip_handler_means_no_report(
        self, make: Callable[[SecurityDecorator], Any]
    ) -> None:
        geo = MagicMock()

        def initialize() -> None:
            return None

        geo.initialize = initialize
        config, decorator, _ = _decorated(make, fail_on_misconfiguration=True)
        config.geo_ip_handler = geo
        initializer = HandlerInitializer(
            config, guard_decorator=decorator, geo_ip_handler=geo
        )

        with warnings.catch_warnings():
            warnings.simplefilter("error")
            initializer.initialize_redis_handlers()


def test_other_decorators_and_no_decorator_never_report() -> None:
    config, decorator, _ = _decorated(
        lambda d: d.rate_limit(5, 60), fail_on_misconfiguration=True
    )

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        HandlerInitializer(
            config, guard_decorator=decorator
        ).initialize_redis_handlers()
        HandlerInitializer(config).initialize_redis_handlers()


def test_the_report_names_the_decorator_in_use(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config, decorator, _ = _decorated(
        lambda d: d.geo_rate_limit({"*": (5, 60)}), fail_on_misconfiguration=False
    )

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        HandlerInitializer(
            config, guard_decorator=decorator
        ).initialize_redis_handlers()

    assert "geo_rate_limit" in caplog.text
    assert "block_countries" not in caplog.text
