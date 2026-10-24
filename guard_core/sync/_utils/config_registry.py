import weakref
from collections.abc import Hashable
from functools import partial
from typing import Any


class ConfigHandlerRegistry:
    """Maps a SecurityConfig, by identity, to a handler built for it.

    The handler is held weakly, so the registry never keeps an app's connection
    alive, and the entry is dropped when either the handler or the config is
    collected (the config's id may then be reused by another object). A component
    that was not handed the handler, such as a released adapter that builds its own
    contexts, finds it here by the config it already holds. ``kind`` lets one
    registry hold several handler kinds for the same config.
    """

    def __init__(self) -> None:
        self._entries: dict[tuple[Hashable, int], weakref.ref[Any]] = {}

    def register(self, config: Any, handler: Any, kind: Hashable = None) -> None:
        key = (kind, id(config))
        self._entries[key] = weakref.ref(handler, partial(self._forget, key))
        try:
            weakref.finalize(config, self._entries.pop, key, None)
        except TypeError:
            pass

    def _forget(self, key: tuple[Hashable, int], _dead: Any = None) -> None:
        self._entries.pop(key, None)

    def drop(self, config: Any, kind: Hashable = None) -> None:
        self._entries.pop((kind, id(config)), None)

    def lookup(self, config: Any, kind: Hashable = None) -> Any | None:
        key = (kind, id(config))
        entry = self._entries.get(key)
        if entry is None:
            return None
        handler = entry()
        if handler is None:
            self._entries.pop(key, None)
        return handler


REDIS_HANDLERS = ConfigHandlerRegistry()
