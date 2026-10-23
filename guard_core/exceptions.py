class GuardCoreError(Exception):
    pass


class GuardRedisError(GuardCoreError):
    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


class AgentPackageNotInstalledError(GuardCoreError):
    pass


class DownloaderNotInstalledError(GuardCoreError, ValueError):
    pass


class GeoDatabaseLoadError(GuardCoreError):
    """Loading the GeoIP database raised, so a country rule cannot be evaluated.

    Raised for every request that needs the database until a later attempt
    succeeds, so ``fail_secure`` answers it as it answered the load error itself.
    """

    def __init__(self, failure: str) -> None:
        self.detail = f"GeoIP database load failed: {failure}"
        super().__init__(self.detail)


class BodyReadStalledError(GuardCoreError):
    """The client stopped sending the request body for longer than the idle timeout.

    An adapter raises it from ``read_body_prefix_until_idle`` when no byte
    arrives for ``idle_timeout`` seconds, and a sync adapter raises it when the
    server's socket timeout fires on the body read. guard-core answers 408.
    """

    def __init__(self, detail: str = "no request body byte arrived in time") -> None:
        self.detail = detail
        super().__init__(detail)


class BodyReadSlotsExhaustedError(BodyReadStalledError):
    """No body read slot became free within ``body_read_timeout``."""

    def __init__(self, max_concurrent: int) -> None:
        self.max_concurrent = max_concurrent
        super().__init__(
            f"no body read slot became free in time (max_concurrent={max_concurrent})"
        )


class BodyReadFailedError(GuardCoreError):
    """Reading the request body failed (a dropped connection, an adapter error).

    guard-core answers 400.
    """

    def __init__(self, detail: str = "the request body could not be read") -> None:
        self.detail = detail
        super().__init__(detail)


class ResponseBodyUnavailableError(AttributeError):
    """``.body`` of the response a ``custom_response_modifier`` received is unavailable.

    An AttributeError subclass so ``hasattr`` and ``getattr(..., default)`` keep
    working. ``reason`` says why: no declared Content-Length, a declared length
    over ``custom_response_modifier_max_body_bytes``, ``text/event-stream``, a
    HEAD, 204 or 304 response, or an adapter without a bounded body reader.
    Header edits made before the access still apply.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(
            f"response body unavailable to custom_response_modifier: {reason}"
        )


class CallableShapeError(TypeError):
    """A callable in the sync tree is async, or hands back an awaitable.

    Raised for ``custom_request_check`` and ``custom_response_modifier``, whose
    sync (WSGI) tree cannot await anything. It is never swallowed: a modifier's
    own errors are logged and the response goes out unmodified, a wrong shape is
    a misconfiguration.
    """

    def __init__(self, field: str) -> None:
        self.field = field
        super().__init__(
            f"{field} is an async callable, or returns an awaitable, and the sync "
            "tree (guard_core.sync, WSGI deployments) cannot await it: supply a "
            "sync callable"
        )
