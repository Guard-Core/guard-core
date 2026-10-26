from unittest.mock import MagicMock


def mock_agent(handler: object) -> MagicMock:
    assert isinstance(handler, MagicMock)
    return handler
