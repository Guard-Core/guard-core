from typing import Protocol, runtime_checkable

from guard_core.protocols.response_protocol import GuardResponse, GuardResponseFactory

__all__ = [
    "GuardResponse",
    "GuardResponseFactory",
    "SyncBoundedResponseBodyReader",
]


@runtime_checkable
class SyncBoundedResponseBodyReader(Protocol):
    """Optional capability: read a size-capped prefix of the response body.

    WHAT: lets a caller read at most ``max_bytes`` of the response body
    without buffering the rest, and without disrupting delivery of the full
    body to the client afterward.
    WHEN: consulted by behavioral ``return_pattern`` rules (``json:``,
    ``regex:``, bare-substring) when ``SecurityConfig.behavior_scan_response_body``
    is enabled, so the response can be pattern-matched up to a bound instead
    of forcing the whole body into memory or being silently skipped.
    HOW: the blocking mirror of ``BoundedResponseBodyReader``. Adapters
    implement this alongside ``GuardResponse`` by teeing their outgoing body
    stream: consume chunks from the underlying stream, buffering only up to
    ``max_bytes``, and return that prefix. The response object must still
    deliver its complete, unbounded body to the client afterward exactly as
    if this method had never been called. It is a separate, optional
    protocol: an adapter that only implements ``GuardResponse`` is still
    fully valid, and callers must treat the absence of this capability as
    "cannot bound the read" and skip body-based pattern matching for that
    response entirely.

    MODIFIER BODY CONTRACT (``custom_response_modifier``'s ``.body``): the
    engine also calls ``read_body_prefix(max_bytes)`` for a modifier that reads
    ``.body``, only when the response declares a ``Content-Length`` up to
    ``SecurityConfig.custom_response_modifier_max_body_bytes`` (never for
    ``text/event-stream``, HEAD, 204 or 304), once per response and shared with
    a ``return_pattern`` scan. For that call ``max_bytes`` covers the declared
    length, so the implementation MUST return the whole body (every chunk up to
    ``max_bytes``) and not stop at the first chunk; the engine hands the bytes
    to the modifier only when their length equals the declared
    ``Content-Length`` and otherwise raises
    ``guard_core.exceptions.ResponseBodyUnavailableError`` from ``.body``. An
    adapter's own ``GuardResponse.body`` is never given to a modifier: the
    engine passes a view whose ``.body`` raises that error (an AttributeError)
    unless the gate allows it, and whose header writes reach the real response
    when the call is committed.

    STREAMING CONTRACT: implementations MUST NOT consume the underlying
    stream to completion to satisfy this call, and MUST NOT block waiting
    for more data than the stream is currently ready to produce. An
    indefinite stream (server-sent events, long polling) may never produce
    ``max_bytes`` of data; a call that waits for it to do so stalls the
    response indefinitely.

    DETECTION LIMIT: only the returned prefix is ever scanned. A payload
    placed after the first ``max_bytes`` of the body, or a signature split
    across the ``max_bytes`` boundary, is not detected.

    MEMORY OBLIGATION (mirrors ``SyncBoundedBodyReader`` /
    GHSA-xv6g-49vj-7w9c): the caller defensively slices the returned bytes
    to ``max_bytes``, but that slice only trims what the implementation
    already returned; it cannot stop an implementation from reading or
    buffering more than ``max_bytes`` internally before returning, and it
    cannot force a streaming response to keep streaming to the client
    afterward. Implementations MUST NOT buffer more than ``max_bytes``
    while producing the prefix, and MUST leave the response able to
    deliver its full, unbounded body to the client exactly as if this
    method had never been called -- guard-core has no way to enforce
    either obligation from the caller side.
    """

    def read_body_prefix(self, max_bytes: int) -> bytes:
        """Return up to ``max_bytes`` of the body, read from its start,
        without disrupting delivery of the remainder to the client."""
        ...
