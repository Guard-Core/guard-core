class GuardCoreError(Exception):
    pass


class GuardRedisError(GuardCoreError):
    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


class AgentPackageNotInstalledError(GuardCoreError):
    pass


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
