from contextvars import ContextVar
from typing import Protocol, cast, runtime_checkable

from guard_core._utils.body_reader import _safe_read
from guard_core._utils.capability import has_callable
from guard_core.protocols.response_protocol import GuardResponse


@runtime_checkable
class _BoundedResponseBodyReader(Protocol):
    async def read_body_prefix(self, max_bytes: int) -> bytes: ...


class ResponseBodyPrefetch:
    """One bounded read of a response body, shared by every consumer of that response.

    The return_pattern scan and the custom_response_modifier replay both ask for
    a prefix; the adapter's ``read_body_prefix`` runs once and each consumer gets
    a slice. A second call happens only when a consumer asks for more bytes than
    the first one read and the first read may have been cut by its own cap.
    """

    __slots__ = ("response", "chunks", "requested", "failed")

    def __init__(self, response: GuardResponse) -> None:
        self.response = response
        self.chunks: list[bytes] = []
        self.requested = 0
        self.failed = False

    async def read(self, max_bytes: int, timeout: float) -> bytes | None:
        if self.requested == 0 or (
            max_bytes > self.requested and self._first_read_may_be_cut()
        ):
            await self._read_from_adapter(max_bytes, timeout)
        if self.failed:
            return None
        return b"".join(self.chunks)[:max_bytes]

    def _first_read_may_be_cut(self) -> bool:
        return sum(map(len, self.chunks)) >= self.requested

    async def _read_from_adapter(self, max_bytes: int, timeout: float) -> None:
        self.requested = max_bytes
        if not has_callable(self.response, "read_body_prefix"):
            self.failed = True
            return
        response = cast(_BoundedResponseBodyReader, self.response)
        prefix: object = await _safe_read(
            lambda: response.read_body_prefix(max_bytes), timeout
        )
        if not isinstance(prefix, bytes):
            self.failed = True
            self.chunks = []
            return
        self.failed = False
        self.chunks = [prefix] if prefix else []


SHARED_PREFETCH: ContextVar[ResponseBodyPrefetch | None] = ContextVar(
    "guard_core_shared_response_prefetch", default=None
)


async def read_shared_prefix(
    response: GuardResponse, max_bytes: int, timeout: float
) -> bytes | None:
    prefetch = SHARED_PREFETCH.get()
    if prefetch is None or prefetch.response is not response:
        prefetch = ResponseBodyPrefetch(response)
    return await prefetch.read(max_bytes, timeout)
