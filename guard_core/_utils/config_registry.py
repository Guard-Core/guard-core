import weakref
from typing import Any


class ConfigHandlerRegistry:
    """Maps a SecurityConfig, by identity, to a handler that was built for it.

    The handler is held weakly, so the registry never keeps an app's connection
    alive. A component that was not handed the handler (a released adapter that
    builds its own contexts) finds it here by the config it already holds.
    """

    def __init__(self) -> None:
        self._entries: dict[int, weakref.ref[Any]] = {}

    def register(self, config: Any, handler: Any) -> None:
        self._entries[id(config)] = weakref.ref(handler)

    def lookup(self, config: Any) -> Any | None:
        entry = self._entries.get(id(config))
        if entry is None:
            return None
        handler = entry()
        if handler is None:
            del self._entries[id(config)]
        return handler


REDIS_HANDLERS = ConfigHandlerRegistry()
