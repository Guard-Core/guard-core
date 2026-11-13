import gc
import logging
import threading
from collections.abc import Callable
from typing import Any

import pytest

from guard_core.core.routing.context import RoutingContext
from guard_core.core.routing.resolver import RouteConfigResolver
from guard_core.decorators import SecurityDecorator, get_route_id
from guard_core.decorators import base as decorators_base
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest

_LOGGER = logging.getLogger("route_id_unique")
KIND = "route.unknown_to_decorator"


def _config(**overrides: object) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        **overrides,
    )


def _handler() -> Callable[[], None]:
    def handler() -> None:
        return None

    return handler


def _resolve(
    decorator: SecurityDecorator, route_id: str, config: SecurityConfig
) -> tuple[object, MockGuardRequest]:
    resolver = RouteConfigResolver(
        RoutingContext(config=config, logger=_LOGGER, guard_decorator=decorator)
    )
    request = MockGuardRequest(path="/x")
    request.state.guard_route_id = route_id
    return resolver.get_route_config(request), request


def _foreign(records: list[logging.LogRecord]) -> list[tuple[str, ...]]:
    return [
        problem
        for record in records
        for problem in record.__dict__.get("problems", ())
        if problem[0] == KIND
    ]


def test_same_named_functions_of_two_decorators_get_different_ids() -> None:
    first, second = SecurityDecorator(_config()), SecurityDecorator(_config())
    route_a, route_b = _handler(), _handler()

    first.rate_limit(5, 60)(route_a)
    second.rate_limit(9, 60)(route_b)

    assert get_route_id(route_a) != get_route_id(route_b)


def test_the_first_issuer_keeps_the_plain_module_qualname_id() -> None:
    first, second = SecurityDecorator(_config()), SecurityDecorator(_config())
    route_a, route_b = _handler(), _handler()

    first.rate_limit(5, 60)(route_a)
    second.rate_limit(9, 60)(route_b)

    plain = f"{route_a.__module__}.{route_a.__qualname__}"
    assert get_route_id(route_a) == plain
    assert get_route_id(route_b) == f"{plain}#2"


def test_a_route_of_another_decorator_is_reported_foreign_and_takes_no_config(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(fail_on_misconfiguration=False)
    first, second = SecurityDecorator(config), SecurityDecorator(config)
    route_a, route_b = _handler(), _handler()
    first.rate_limit(5, 60)(route_a)
    second.rate_limit(9, 60)(route_b)
    foreign_id = get_route_id(route_b)

    with caplog.at_level(logging.WARNING):
        resolved, request = _resolve(first, foreign_id, config)
        _resolve(first, foreign_id, config)

    assert resolved is None
    assert request.state.guard_route_unresolved is True
    assert _foreign(caplog.records) == [(KIND, foreign_id)]


def test_each_decorator_still_resolves_its_own_route() -> None:
    config = _config()
    first, second = SecurityDecorator(config), SecurityDecorator(config)
    route_a, route_b = _handler(), _handler()
    first.rate_limit(5, 60)(route_a)
    second.rate_limit(9, 60)(route_b)

    own_a, _ = _resolve(first, get_route_id(route_a), config)
    own_b, _ = _resolve(second, get_route_id(route_b), config)

    assert (getattr(own_a, "rate_limit", None), getattr(own_b, "rate_limit", None)) == (
        5,
        9,
    )


def test_a_function_decorated_by_two_decorators_keeps_one_id_and_both_configs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(fail_on_misconfiguration=False)
    first, second = SecurityDecorator(config), SecurityDecorator(config)
    shared = _handler()

    first.rate_limit(5, 60)(shared)
    stamped = get_route_id(shared)
    second.rate_limit(9, 60)(shared)

    assert get_route_id(shared) == stamped
    with caplog.at_level(logging.WARNING):
        seen_by_first, _ = _resolve(first, stamped, config)
        seen_by_second, _ = _resolve(second, stamped, config)
    assert getattr(seen_by_first, "rate_limit", None) == 5
    assert getattr(seen_by_second, "rate_limit", None) == 9
    assert not _foreign(caplog.records)


def test_a_shared_function_does_not_take_the_id_of_a_same_named_other_function() -> (
    None
):
    first, second = SecurityDecorator(_config()), SecurityDecorator(_config())
    shared, other = _handler(), _handler()
    first.rate_limit(5, 60)(shared)
    second.rate_limit(9, 60)(shared)

    second.rate_limit(7, 60)(other)

    assert get_route_id(other) != get_route_id(shared)


def test_dropped_decorators_leave_the_registry_at_its_start_size() -> None:
    gc.collect()
    start = len(decorators_base._LIVE_DECORATORS)

    for _ in range(25):
        dropped = SecurityDecorator(_config())
        dropped.rate_limit(5, 60)(_handler())
        del dropped
    gc.collect()

    assert len(decorators_base._LIVE_DECORATORS) == start


def test_dropped_decorators_release_their_ids() -> None:
    survivor = SecurityDecorator(_config())
    for _ in range(5):
        dropped = SecurityDecorator(_config())
        dropped.rate_limit(5, 60)(_handler())
        del dropped
    gc.collect()
    route = _handler()

    survivor.rate_limit(5, 60)(route)

    assert get_route_id(route) == f"{route.__module__}.{route.__qualname__}"


def test_decorators_decorating_in_parallel_never_share_an_id() -> None:
    workers = 8
    barrier = threading.Barrier(workers)
    ids: list[str] = []
    alive: list[SecurityDecorator] = []
    guard_lock = threading.Lock()

    def work() -> None:
        decorator = SecurityDecorator(_config())
        route = _handler()
        barrier.wait()
        decorator.rate_limit(5, 60)(route)
        with guard_lock:
            alive.append(decorator)
            ids.append(get_route_id(route))

    threads: list[Any] = [threading.Thread(target=work) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(set(ids)) == workers
