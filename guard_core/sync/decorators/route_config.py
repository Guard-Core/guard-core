from collections.abc import Callable
from typing import (
    TYPE_CHECKING,
    Any,
    SupportsIndex,
)

from guard_core.sync.protocols.request_protocol import SyncGuardRequest

if TYPE_CHECKING:
    from guard_core.sync.handlers.behavior_handler import BehaviorRule

Principal = Any
AuthVerifier = Callable[[SyncGuardRequest, str], Any]


class RouteConfigRevision:
    def __init__(self) -> None:
        self.value = 0

    def bump(self) -> None:
        self.value += 1


class _RevisionTrackedContainer:
    _revision: RouteConfigRevision | None

    def _bump(self) -> None:
        if self._revision is not None:
            self._revision.bump()


class _TrackedList(_RevisionTrackedContainer, list):
    def __init__(
        self,
        iterable: Any = (),
        *,
        revision: RouteConfigRevision | None = None,
    ) -> None:
        list.__init__(self, iterable)
        self._revision = revision

    def append(self, item: Any) -> None:
        self._bump()
        list.append(self, item)

    def extend(self, iterable: Any) -> None:
        self._bump()
        list.extend(self, iterable)

    def insert(self, index: SupportsIndex, item: Any) -> None:
        self._bump()
        list.insert(self, index, item)

    def remove(self, item: Any) -> None:
        self._bump()
        list.remove(self, item)

    def pop(self, index: SupportsIndex = -1) -> Any:
        self._bump()
        return list.pop(self, index)

    def clear(self) -> None:
        self._bump()
        list.clear(self)

    def sort(self, *args: Any, **kwargs: Any) -> None:
        self._bump()
        list.sort(self, *args, **kwargs)

    def reverse(self) -> None:
        self._bump()
        list.reverse(self)

    def __setitem__(self, key: Any, value: Any) -> None:
        self._bump()
        list.__setitem__(self, key, value)

    def __delitem__(self, key: Any) -> None:
        self._bump()
        list.__delitem__(self, key)

    def __add__(self, other: Any) -> Any:
        return list.__add__(self, other)

    def __mul__(self, other: Any) -> Any:
        return list.__mul__(self, other)

    def __iadd__(self, other: Any) -> Any:
        self._bump()
        list.__iadd__(self, other)
        return self

    def __imul__(self, other: Any) -> Any:
        self._bump()
        list.__imul__(self, other)
        return self


class _TrackedDict(_RevisionTrackedContainer, dict):
    def __init__(
        self,
        mapping: Any = (),
        *,
        revision: RouteConfigRevision | None = None,
    ) -> None:
        dict.__init__(self, mapping)
        self._revision = revision

    def __setitem__(self, key: Any, value: Any) -> None:
        self._bump()
        dict.__setitem__(self, key, value)

    def __delitem__(self, key: Any) -> None:
        self._bump()
        dict.__delitem__(self, key)

    def update(self, *args: Any, **kwargs: Any) -> None:
        self._bump()
        dict.update(self, *args, **kwargs)

    def setdefault(self, key: Any, default: Any = None) -> Any:
        self._bump()
        return dict.setdefault(self, key, default)

    def pop(self, *args: Any) -> Any:
        self._bump()
        return dict.pop(self, *args)

    def popitem(self) -> tuple[Any, Any]:
        self._bump()
        return dict.popitem(self)

    def clear(self) -> None:
        self._bump()
        dict.clear(self)

    def __or__(self, other: Any) -> Any:
        return dict.__or__(self, other)

    def __ior__(self, other: Any) -> Any:
        self._bump()
        dict.__ior__(self, other)
        return self


class _TrackedSet(_RevisionTrackedContainer, set):
    def __init__(
        self,
        iterable: Any = (),
        *,
        revision: RouteConfigRevision | None = None,
    ) -> None:
        set.__init__(self, iterable)
        self._revision = revision

    def add(self, item: Any) -> None:
        self._bump()
        set.add(self, item)

    def discard(self, item: Any) -> None:
        self._bump()
        set.discard(self, item)

    def remove(self, item: Any) -> None:
        self._bump()
        set.remove(self, item)

    def pop(self) -> Any:
        self._bump()
        return set.pop(self)

    def clear(self) -> None:
        self._bump()
        set.clear(self)

    def update(self, *others: Any) -> None:
        self._bump()
        set.update(self, *others)

    def intersection_update(self, *others: Any) -> None:
        self._bump()
        set.intersection_update(self, *others)

    def difference_update(self, *others: Any) -> None:
        self._bump()
        set.difference_update(self, *others)

    def symmetric_difference_update(self, other: Any) -> None:
        self._bump()
        set.symmetric_difference_update(self, other)

    def __or__(self, other: Any) -> Any:
        return set.__or__(self, other)

    def __and__(self, other: Any) -> Any:
        return set.__and__(self, other)

    def __sub__(self, other: Any) -> Any:
        return set.__sub__(self, other)

    def __xor__(self, other: Any) -> Any:
        return set.__xor__(self, other)

    def __ior__(self, other: Any) -> Any:
        self._bump()
        set.__ior__(self, other)
        return self

    def __iand__(self, other: Any) -> Any:
        self._bump()
        set.__iand__(self, other)
        return self

    def __isub__(self, other: Any) -> Any:
        self._bump()
        set.__isub__(self, other)
        return self

    def __ixor__(self, other: Any) -> Any:
        self._bump()
        set.__ixor__(self, other)
        return self


_TRACKED_LIST_FIELDS = frozenset(
    {
        "custom_validators",
        "require_referrer",
        "allowed_content_types",
        "blocked_user_agents",
    }
)
_TRACKED_DICT_FIELDS = frozenset(
    {"required_headers", "time_restrictions", "geo_rate_limits"}
)
_TRACKED_SET_FIELDS = frozenset({"block_cloud_providers"})
_REVISION_EXEMPT_ATTRS = frozenset({"_revision", "_initialized"})


class RouteConfig:
    _revision: RouteConfigRevision | None
    _initialized: bool

    def __init__(self, revision: RouteConfigRevision | None = None) -> None:
        object.__setattr__(self, "_revision", revision)
        object.__setattr__(self, "_initialized", False)
        self.rate_limit: int | None = None
        self.rate_limit_window: int | None = None
        self.ip_whitelist: list[str] | None = None
        self.ip_blacklist: list[str] | None = None
        self.blocked_countries: list[str] | None = None
        self.whitelist_countries: list[str] | None = None
        self.bypassed_checks: set[str] = set()
        self.require_https: bool = False
        self.auth_required: str | None = None
        self.custom_validators: list[Callable] = []
        self.blocked_user_agents: list[str] = []
        self.required_headers: dict[str, str] = {}
        self.behavior_rules: list[BehaviorRule] = []
        self.block_cloud_providers: set[str] = set()
        self.max_request_size: int | None = None
        self.allowed_content_types: list[str] | None = None
        self.time_restrictions: dict[str, str] | None = None
        self.enable_suspicious_detection: bool = True
        self.require_referrer: list[str] | None = None
        self.api_key_required: bool = False
        self.auth_verifier: AuthVerifier | None = None
        self.api_key_verifier: AuthVerifier | None = None
        self.api_key_header: str | None = None
        self.authorization_header_required: str | None = None
        self.geo_rate_limits: dict[str, tuple[int, int]] | None = None
        self.excluded_detection_headers: set[str] | None = None
        self.excluded_semantic_detection_headers: set[str] | None = None
        self.excluded_detection_params: set[str] | None = None
        self.excluded_detection_body_fields: set[str] | None = None
        self.enabled_detection_categories: set[str] | None = None
        self.detection_scan_body: bool | None = None
        object.__setattr__(self, "_initialized", True)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in _TRACKED_LIST_FIELDS and isinstance(value, list):
            value = _TrackedList(value, revision=self._revision)
        elif name in _TRACKED_DICT_FIELDS and isinstance(value, dict):
            value = _TrackedDict(value, revision=self._revision)
        elif name in _TRACKED_SET_FIELDS and isinstance(value, set):
            value = _TrackedSet(value, revision=self._revision)
        object.__setattr__(self, name, value)
        if self._initialized and name not in _REVISION_EXEMPT_ATTRS:
            revision = self._revision
            if revision is not None:
                revision.bump()
