from typing import Any
from unittest.mock import NonCallableMock


def mock_agent(handler: object) -> Any:
    assert isinstance(handler, NonCallableMock)
    return handler


def mock_redis(handler: object) -> Any:
    assert isinstance(handler, NonCallableMock)
    return handler


def redis_slot(fake: object) -> Any:
    return fake
