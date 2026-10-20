import logging

_RAISE_HINT = (
    "Raise IPInfoManager._download_max_bytes if the database legitimately grew."
)


def reject_declared_size(
    declared: int | None, cap: int, logger: logging.Logger
) -> None:
    if declared is not None and declared > cap:
        _reject("declares", declared, cap, logger)


def reject_received_size(received: int, cap: int, logger: logging.Logger) -> None:
    if received > cap:
        _reject("has sent at least", received, cap, logger)


def _reject(verb: str, size: int, cap: int, logger: logging.Logger) -> None:
    message = (
        f"GeoIP download rejected: the response {verb} {size} bytes, "
        f"over the cap of {cap} bytes."
    )
    logger.error("%s %s", message, _RAISE_HINT)
    raise TimeoutError(message)
