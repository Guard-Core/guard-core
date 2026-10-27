from collections.abc import Iterable
from typing import Protocol, runtime_checkable


class GuardResponseHeaders(Protocol):
    """The header container of a response: exactly what the engine calls on it.

    WHAT: the members the engine reads and writes on ``GuardResponse.headers``
    and nothing more. Not a ``MutableMapping``: Werkzeug ``Headers`` iterates
    ``(name, value)`` pairs and a Django response iterates its body, so
    ``__iter__`` and ``__len__`` are not part of the surface; ``keys()`` and
    ``items()`` are, because the engine reads them (header casing, undo of a
    modifier's writes) and the adapters copy the headers back out with them.
    WHEN: every time the engine attaches ``Retry-After``, ``Allow``,
    ``WWW-Authenticate``, CORS or security headers to a response, and when it
    reads ``content-type`` and ``content-length`` to decide whether a body may
    be offered to a ``custom_response_modifier``.
    HOW: pass the framework's own header object (Werkzeug ``Headers``, Django
    ``ResponseHeaders``, Starlette ``MutableHeaders``, Tornado ``HTTPHeaders``)
    or a plain ``dict[str, str]``. Lookups use the container's own casing rules;
    only a plain ``dict`` is case-sensitive and the engine adds a casing
    fallback for it. ``append(name, value)`` (Starlette ``MutableHeaders``) is an
    optional extra the engine uses when present.
    """

    def __getitem__(self, key: str, /) -> str:
        """The value stored under ``key``; ``KeyError`` (or a subclass) when absent."""
        ...

    def __setitem__(self, key: str, value: str, /) -> None:
        """Set ``key`` to ``value``, replacing any value it held."""
        ...

    def __delitem__(self, key: str, /) -> None:
        """Remove ``key``; ``KeyError`` (or a subclass) when absent."""
        ...

    def __contains__(self, key: str, /) -> bool:
        """Whether a header named ``key`` is set."""
        ...

    def get(self, key: str, /) -> str | None:
        """The value stored under ``key``, or ``None`` when absent."""
        ...

    def keys(self) -> Iterable[str]:
        """The header names; ``dict(headers)`` and ``{**headers}`` read it."""
        ...

    def items(self) -> Iterable[tuple[str, str]]:
        """The ``(name, value)`` pairs, as the adapter copies them back out."""
        ...


@runtime_checkable
class GuardResponse(Protocol):
    """Framework-agnostic view of a response the engine returns or inspects.

    WHAT: the minimal surface (status, headers, body) the engine reads from a
    block/redirect response and the adapter renders back to the framework.
    WHEN: produced by ``GuardResponseFactory`` when a check denies a request,
    and read by the adapter to emit the real framework response.
    HOW: wrap the framework's response object; ``headers`` is mutable so the
    engine can attach security headers before the response is sent.
    """

    @property
    def status_code(self) -> int:
        """The HTTP status code."""
        ...

    @property
    def headers(self) -> GuardResponseHeaders:
        """The response headers; mutable so the engine can add/override them."""
        ...

    @property
    def body(self) -> bytes | None:
        """The response body, or ``None`` when there is no body."""
        ...


@runtime_checkable
class GuardResponseFactory(Protocol):
    """Builds the responses the engine returns when a check denies a request.

    WHAT: the seam that lets the engine emit error/redirect responses without
    knowing the concrete framework response type.
    WHEN: called by checks at the moment of a block to construct the outgoing
    ``GuardResponse``.
    HOW: return objects satisfying ``GuardResponse``; keep construction pure
    (no I/O), as these run inline on the request path.
    """

    def create_response(self, content: str, status_code: int) -> GuardResponse:
        """Build a response carrying ``content`` and ``status_code``."""
        ...

    def create_redirect_response(self, url: str, status_code: int) -> GuardResponse:
        """Build a redirect response pointing at ``url`` with ``status_code``."""
        ...


@runtime_checkable
class BoundedResponseBodyReader(Protocol):
    """Optional capability: read a size-capped prefix of the response body.

    WHAT: lets a caller read at most ``max_bytes`` of the response body
    without buffering the rest, and without disrupting delivery of the full
    body to the client afterward.
    WHEN: consulted by behavioral ``return_pattern`` rules (``json:``,
    ``regex:``, bare-substring) when ``SecurityConfig.behavior_scan_response_body``
    is enabled, so the response can be pattern-matched up to a bound instead
    of forcing the whole body into memory or being silently skipped. Unlike
    the request side, the eager ``GuardResponse.body`` accessor is not a safe
    fallback here: adapters may implement it as a property that raises for a
    response whose body is not yet fully materialized (a streaming response
    in particular), and that raise is indistinguishable from "no body" to a
    caller that cannot see inside the property. This capability is the only
    sanctioned way to read response body bytes for pattern matching.
    HOW: adapters implement this alongside ``GuardResponse`` by teeing their
    outgoing body stream: consume chunks from the underlying stream,
    buffering only up to ``max_bytes``, and return that prefix. The response
    object must still deliver its complete, unbounded body to the client
    afterward exactly as if this method had never been called -- typically
    by replacing the body iterator with one that first replays the captured
    prefix, then continues the original iterator untouched. It is a
    separate, optional protocol: an adapter that only implements
    ``GuardResponse`` is still fully valid, and callers must treat the
    absence of this capability as "cannot bound the read" and skip
    body-based pattern matching for that response entirely.

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
    response indefinitely. Return whatever prefix is available from the
    chunks already produced when a natural stopping point is reached (for
    example, after the first chunk, or once ``max_bytes`` is reached,
    whichever comes first) rather than blocking for exactly ``max_bytes``.

    DETECTION LIMIT: only the returned prefix is ever scanned. A payload
    placed after the first ``max_bytes`` of the body, or a signature split
    across the ``max_bytes`` boundary, is not detected. This is the
    memory/detection tradeoff bounded-memory scanning makes on purpose; it
    is not equivalent to scanning the full body and must not be presented
    as such.

    MEMORY OBLIGATION (mirrors ``BoundedBodyReader`` /
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

    async def read_body_prefix(self, max_bytes: int) -> bytes:
        """Return up to ``max_bytes`` of the body, read from its start,
        without disrupting delivery of the remainder to the client."""
        ...


@runtime_checkable
class MaterializedBodyResponse(Protocol):
    """Optional capability: the response body is already fully in memory.

    WHAT: a ``body_is_materialized`` property that is exactly ``True`` when the
    response holds its whole body in memory, so reading ``body`` costs nothing
    and consumes nothing.
    WHEN: read once per response by ``custom_response_modifier`` handling. When
    it is ``True`` the modifier gets the real response exactly as before the
    bounded-body feature: real ``body`` bytes, one call, no view, no prefetch,
    no replay and no ``custom_response_modifier_max_body_bytes`` cap. Absent,
    ``False`` or any other value keeps the bounded path (a custom or third-party
    response is never assumed materialized).
    HOW: derive it from the framework's own signal, read before anything
    touches the body: Starlette ``Response`` holds ``body`` (``FileResponse`` and
    ``StreamingResponse`` do not), Django ``not response.streaming``, Werkzeug
    ``not response.is_streamed`` read before ``.data`` (which buffers and flips
    it), Tornado a buffered write rather than a chunked one.
    """

    @property
    def body_is_materialized(self) -> bool:
        """True when the whole body is already in memory."""
        ...
