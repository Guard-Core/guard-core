from typing import Any, NamedTuple


class RouteIdentity(NamedTuple):
    """The handler a router dispatches to, plus the path parameters it captured.

    WHAT: an in-process dict key, never persisted and never sent to Redis.
    WHEN: an adapter builds one for the current request and for every route a
    configured endpoint rate limit key reaches, so the two can be compared.
    HOW: ``handler`` is the dispatched object itself (function, class plus
    method name tuple, ...), never a qualname string, so two handlers that
    share a name never compare equal. ``path_params`` holds the router's
    converted values as strings, sorted by name, positional args as "0", "1".
    """

    handler: Any
    path_params: tuple[tuple[str, str], ...]
