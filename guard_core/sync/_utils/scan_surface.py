from guard_core.exceptions import RegexQueueWaitError

_SCAN_SURFACE_NAMES = {
    "url_path": "url path",
    "query_param": "query",
    "header": "header",
    "request_body": "body field",
}


def note_scan_surface(error: BaseException, context: str) -> None:
    """Record on a queue-wait error the fixed name of what was being scanned (the
    first scan that met it wins), for a log line and an event that must never
    carry a request value."""
    if isinstance(error, RegexQueueWaitError) and error.surface is None:
        error.surface = _SCAN_SURFACE_NAMES.get(context.split(":", 1)[0])
