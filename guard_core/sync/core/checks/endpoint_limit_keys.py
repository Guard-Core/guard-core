from collections.abc import Callable, Iterable

from guard_core.protocols.route_identity import RouteIdentity
from guard_core.sync._utils.request_path import resolve_dot_and_empty_segments

RouteResolver = Callable[[str], tuple[RouteIdentity, ...]]


def normalize_limit_path(path: str) -> str:
    resolved = resolve_dot_and_empty_segments(path)
    if len(resolved) > 1 and resolved.endswith("/"):
        return resolved[:-1]
    return resolved


class EndpointLimitKeyMap:
    def __init__(
        self, keys: Iterable[str], resolve_route: RouteResolver | None
    ) -> None:
        self.keys = frozenset(keys)
        by_identity: dict[RouteIdentity, set[str]] = {}
        by_path: dict[str, set[str]] = {}
        unresolved: set[str] = set()
        for key in self.keys:
            by_path.setdefault(normalize_limit_path(key), set()).add(key)
            if resolve_route is None:
                continue
            identities = resolve_route(key)
            if not identities:
                unresolved.add(key)
            for identity in identities:
                by_identity.setdefault(identity, set()).add(key)
        self.unresolved = frozenset(unresolved)
        self.by_identity = {k: frozenset(v) for k, v in by_identity.items()}
        self.by_path = {k: frozenset(v) for k, v in by_path.items()}

    def matched_keys(
        self, identity: RouteIdentity | None, url_path: str
    ) -> tuple[str, ...]:
        by_route = self.by_identity.get(identity) if identity is not None else None
        matched = by_route or self.by_path.get(
            normalize_limit_path(url_path), frozenset()
        )
        return tuple(sorted(matched))
