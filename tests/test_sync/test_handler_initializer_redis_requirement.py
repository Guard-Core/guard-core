from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer


def test_a_step_that_needs_redis_names_the_missing_handler() -> None:
    initializer = HandlerInitializer(SyncSecurityConfig(enable_redis=False))

    with pytest.raises(RuntimeError, match="needs a redis_handler"):
        initializer._require_redis_handler()


def test_a_step_that_needs_redis_gets_the_configured_handler() -> None:
    redis_handler = MagicMock()
    initializer = HandlerInitializer(
        SyncSecurityConfig(enable_redis=False), redis_handler=redis_handler
    )

    assert initializer._require_redis_handler() is redis_handler
