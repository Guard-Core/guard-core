from collections.abc import AsyncIterator
from unittest.mock import MagicMock


def streamed(content: bytes) -> MagicMock:
    """What `response.content.iter_chunked` returns for a body held in memory."""

    async def chunks(size: int) -> AsyncIterator[bytes]:
        yield content

    return MagicMock(side_effect=chunks)
