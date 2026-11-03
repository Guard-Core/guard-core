from unittest.mock import NonCallableMock


def mock_agent(handler: object) -> NonCallableMock:
    assert isinstance(handler, NonCallableMock)
    return handler


def mock_redis(handler: object) -> NonCallableMock:
    assert isinstance(handler, NonCallableMock)
    return handler


def redis_slot(fake: NonCallableMock) -> NonCallableMock:
    return fake
