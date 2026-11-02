from typing import Any
from unittest.mock import MagicMock

from guard_core.sync.core.checks import _strike_forget
from guard_core.sync.core.checks._strike_forget import (
    forget_category_strikes,
    register_strike_middleware,
)

_kept_alive: list[Any] = []


def test_a_test_may_register_a_mock_middleware_that_outlives_it() -> None:
    middleware = MagicMock()
    _kept_alive.append(middleware)
    register_strike_middleware(middleware)

    assert middleware in _strike_forget._registered_middlewares()


def test_the_next_test_starts_with_an_empty_strike_registry() -> None:
    assert _kept_alive
    assert _strike_forget._registered_middlewares() == []
    forget_category_strikes("rate_limit")
