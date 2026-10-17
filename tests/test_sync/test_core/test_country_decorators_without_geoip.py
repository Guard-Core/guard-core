import warnings
from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.decorators import SecurityDecorator


def _decorated(
    make: Callable[[SecurityDecorator], Any], **flag: bool
) -> tuple[SecurityConfig, SecurityDecorator, str]:
    config = SecurityConfig(enable_redis=False, **flag)
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
    def test_unset_flag_warns_naming_the_route(
        self, make: Callable[[SecurityDecorator], Any]
    ) -> None:
        config, decorator, route_id = _decorated(make)
        initializer = HandlerInitializer(config, guard_decorator=decorator)

        with pytest.warns(DeprecationWarning) as caught:
            initializer.initialize_redis_handlers()

        message = str(caught[0].message)
        assert route_id in message
        assert "no GeoIP database" in message
        assert "fail_on_misconfiguration is not set" in message

    def test_true_raises_at_startup(
        self, make: Callable[[SecurityDecorator], Any]
    ) -> None:
        config, decorator, route_id = _decorated(make, fail_on_misconfiguration=True)
        initializer = HandlerInitializer(config, guard_decorator=decorator)

        with pytest.raises(ValueError, match="no GeoIP database"):
            initializer.initialize_redis_handlers()

    def test_false_warns_without_the_not_set_part(
        self, make: Callable[[SecurityDecorator], Any]
    ) -> None:
        config, decorator, _ = _decorated(make, fail_on_misconfiguration=False)
        initializer = HandlerInitializer(config, guard_decorator=decorator)

        with pytest.warns(DeprecationWarning, match="keeps starting") as caught:
            initializer.initialize_redis_handlers()

        assert "is not set" not in str(caught[0].message)

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


def test_the_report_names_the_decorator_in_use() -> None:
    config, decorator, _ = _decorated(lambda d: d.geo_rate_limit({"*": (5, 60)}))

    with pytest.warns(DeprecationWarning, match="geo_rate_limit") as caught:
        HandlerInitializer(
            config, guard_decorator=decorator
        ).initialize_redis_handlers()

    assert "block_countries" not in str(caught[0].message)
