from collections.abc import Callable, Iterable, Mapping
from collections.abc import Set as AbstractSet
from typing import (
    TYPE_CHECKING,
    Concatenate,
    ParamSpec,
    SupportsIndex,
    TypeVar,
    overload,
)

from typing_extensions import Self

from guard_core.sync.protocols.request_protocol import SyncGuardRequest

if TYPE_CHECKING:
    from _typeshed import SupportsKeysAndGetItem, SupportsRichComparison

    from guard_core.sync.handlers.behavior_handler import BehaviorRule

    _Updates = SupportsKeysAndGetItem[str, object] | Iterable[tuple[str, object]]
    _Slice = slice[SupportsIndex | None, SupportsIndex | None, SupportsIndex | None]

_Item = TypeVar("_Item")
_Key = TypeVar("_Key")
_Value = TypeVar("_Value")
Principal = object
AuthVerifier = Callable[[SyncGuardRequest, str], object]


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
        iterable: Iterable[object] = (),
        *,
        revision: RouteConfigRevision | None = None,
    ) -> None:
        list.__init__(self, iterable)
        self._revision = revision

    def append(self, item: object) -> None:
        try:
            list.append(self, item)
        finally:
            self._bump()

    def extend(self, iterable: Iterable[object]) -> None:
        try:
            list.extend(self, iterable)
        finally:
            self._bump()

    def insert(self, index: SupportsIndex, item: object) -> None:
        try:
            list.insert(self, index, item)
        finally:
            self._bump()

    def remove(self, item: object) -> None:
        try:
            list.remove(self, item)
        finally:
            self._bump()

    def pop(self, index: SupportsIndex = -1) -> object:
        try:
            return list.pop(self, index)
        finally:
            self._bump()

    def clear(self) -> None:
        try:
            list.clear(self)
        finally:
            self._bump()

    def sort(
        self,
        *,
        key: "Callable[[object], SupportsRichComparison] | None" = None,
        reverse: bool = False,
    ) -> None:
        try:
            list.sort(self, key=key, reverse=reverse)
        finally:
            self._bump()

    def reverse(self) -> None:
        try:
            list.reverse(self)
        finally:
            self._bump()

    @overload
    def __setitem__(self, key: SupportsIndex, value: object, /) -> None: ...

    @overload
    def __setitem__(self, key: "_Slice", value: Iterable[object], /) -> None: ...

    def __setitem__(self, key: "SupportsIndex | _Slice", value: object, /) -> None:
        try:
            if not isinstance(key, slice):
                list.__setitem__(self, key, value)
            elif isinstance(value, Iterable):
                list.__setitem__(self, key, value)
            else:
                raise TypeError("must assign iterable to extended slice")
        finally:
            self._bump()

    def __delitem__(self, key: "SupportsIndex | _Slice") -> None:
        try:
            list.__delitem__(self, key)
        finally:
            self._bump()

    def __add__(self, other: list[_Item]) -> list[object | _Item]:
        return list.__add__(self, other)

    def __mul__(self, other: SupportsIndex) -> list[object]:
        return list.__mul__(self, other)

    def __iadd__(self, other: Iterable[object]) -> Self:
        try:
            list.__iadd__(self, other)
            return self
        finally:
            self._bump()

    def __imul__(self, other: SupportsIndex) -> Self:
        try:
            list.__imul__(self, other)
            return self
        finally:
            self._bump()


class _TrackedDict(_RevisionTrackedContainer, dict):
    def __init__(
        self,
        mapping: Mapping[str, object] | Iterable[tuple[str, object]] = (),
        *,
        revision: RouteConfigRevision | None = None,
    ) -> None:
        dict.__init__(self, mapping)
        self._revision = revision

    def __setitem__(self, key: str, value: object) -> None:
        try:
            dict.__setitem__(self, key, value)
        finally:
            self._bump()

    def __delitem__(self, key: str) -> None:
        try:
            dict.__delitem__(self, key)
        finally:
            self._bump()

    def update(
        self,
        other: "_Updates" = (),
        /,
        **kwargs: object,
    ) -> None:
        try:
            dict.update(self, other, **kwargs)
        finally:
            self._bump()

    def setdefault(self, key: str, default: object = None) -> object:
        try:
            return dict.setdefault(self, key, default)
        finally:
            self._bump()

    def pop(self, key: str, *default: object) -> object:
        try:
            return dict.pop(self, key, *default)
        finally:
            self._bump()

    def popitem(self) -> tuple[str, object]:
        try:
            return dict.popitem(self)
        finally:
            self._bump()

    def clear(self) -> None:
        try:
            dict.clear(self)
        finally:
            self._bump()

    def __or__(self, other: dict[_Key, _Value]) -> dict[str | _Key, object | _Value]:
        return dict.__or__(self, other)

    def __ior__(
        self,
        other: "SupportsKeysAndGetItem[_Key, _Value] | Iterable[tuple[_Key, _Value]]",
        /,
    ) -> Self:
        try:
            dict.__ior__(self, other)
            return self
        finally:
            self._bump()


_Arguments = ParamSpec("_Arguments")
_Result = TypeVar("_Result")


def _refusing_an_invalid_window(
    method: Callable[Concatenate["_TrackedTimeRestrictions", _Arguments], _Result],
) -> Callable[Concatenate["_TrackedTimeRestrictions", _Arguments], _Result]:
    def mutate(
        self: "_TrackedTimeRestrictions",
        *args: _Arguments.args,
        **kwargs: _Arguments.kwargs,
    ) -> _Result:
        from guard_core.sync.decorators._route_arguments import (
            time_restriction_problems,
        )

        before = dict(self)
        result = method(self, *args, **kwargs)
        problems = time_restriction_problems(self) if self else []
        if problems:
            dict.clear(self)
            dict.update(self, before)
            raise ValueError(" ".join(problems))
        return result

    return mutate


class _TrackedTimeRestrictions(_TrackedDict):
    __setitem__ = _refusing_an_invalid_window(_TrackedDict.__setitem__)
    __delitem__ = _refusing_an_invalid_window(_TrackedDict.__delitem__)
    update = _refusing_an_invalid_window(_TrackedDict.update)
    setdefault = _refusing_an_invalid_window(_TrackedDict.setdefault)
    pop = _refusing_an_invalid_window(_TrackedDict.pop)
    popitem = _refusing_an_invalid_window(_TrackedDict.popitem)
    __ior__ = _refusing_an_invalid_window(_TrackedDict.__ior__)


class _TrackedSet(_RevisionTrackedContainer, set):
    def __init__(
        self,
        iterable: Iterable[object] = (),
        *,
        revision: RouteConfigRevision | None = None,
    ) -> None:
        set.__init__(self, iterable)
        self._revision = revision

    def add(self, item: object) -> None:
        try:
            set.add(self, item)
        finally:
            self._bump()

    def discard(self, item: object) -> None:
        try:
            set.discard(self, item)
        finally:
            self._bump()

    def remove(self, item: object) -> None:
        try:
            set.remove(self, item)
        finally:
            self._bump()

    def pop(self) -> object:
        try:
            return set.pop(self)
        finally:
            self._bump()

    def clear(self) -> None:
        try:
            set.clear(self)
        finally:
            self._bump()

    def update(self, *others: Iterable[object]) -> None:
        try:
            set.update(self, *others)
        finally:
            self._bump()

    def intersection_update(self, *others: Iterable[object]) -> None:
        try:
            set.intersection_update(self, *others)
        finally:
            self._bump()

    def difference_update(self, *others: Iterable[object]) -> None:
        try:
            set.difference_update(self, *others)
        finally:
            self._bump()

    def symmetric_difference_update(self, other: Iterable[object]) -> None:
        try:
            set.symmetric_difference_update(self, other)
        finally:
            self._bump()

    def __or__(self, other: AbstractSet[_Item]) -> set[object | _Item]:
        return set.__or__(self, other)

    def __and__(self, other: AbstractSet[object]) -> set[object]:
        return set.__and__(self, other)

    def __sub__(self, other: AbstractSet[object]) -> set[object]:
        return set.__sub__(self, other)

    def __xor__(self, other: AbstractSet[_Item]) -> set[object | _Item]:
        return set.__xor__(self, other)

    def __ior__(self, other: AbstractSet[object]) -> Self:
        try:
            set.__ior__(self, other)
            return self
        finally:
            self._bump()

    def __iand__(self, other: AbstractSet[object]) -> Self:
        try:
            set.__iand__(self, other)
            return self
        finally:
            self._bump()

    def __isub__(self, other: AbstractSet[object]) -> Self:
        try:
            set.__isub__(self, other)
            return self
        finally:
            self._bump()

    def __ixor__(self, other: AbstractSet[object]) -> Self:
        try:
            set.__ixor__(self, other)
            return self
        finally:
            self._bump()


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


def _wrap_in_tracked_container(
    name: str, value: object, revision: RouteConfigRevision | None
) -> object:
    if name in _TRACKED_LIST_FIELDS and isinstance(value, list):
        return _TrackedList(value, revision=revision)
    if name == "time_restrictions" and isinstance(value, dict):
        return _TrackedTimeRestrictions(value, revision=revision)
    if name in _TRACKED_DICT_FIELDS and isinstance(value, dict):
        return _TrackedDict(value, revision=revision)
    if name in _TRACKED_SET_FIELDS and isinstance(value, set):
        return _TrackedSet(value, revision=revision)
    return value


class RouteConfig:
    _revision: RouteConfigRevision | None
    _initialized: bool
    _inherits_suspicious_detection: bool

    def __init__(self, revision: RouteConfigRevision | None = None) -> None:
        object.__setattr__(self, "_revision", revision)
        object.__setattr__(self, "_initialized", False)
        object.__setattr__(self, "_inherits_suspicious_detection", False)
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
        self.honeypot_validators: list[Callable] = []
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
        self.excluded_detection_params: set[str] | dict[str, set[str]] | None = None
        self.excluded_detection_path_params: set[str] | dict[str, set[str]] | None = (
            None
        )
        self.excluded_detection_body_fields: set[str] | dict[str, set[str]] | None = (
            None
        )
        self.enabled_detection_categories: set[str] | None = None
        self.detection_scan_body: bool | None = None
        object.__setattr__(self, "_initialized", True)

    def _inherit_suspicious_detection(self, global_setting: bool) -> None:
        # Keeps the v4.4.0 snapshot readable while the request path follows the
        # live global setting until a decorator or an assignment pins the route.
        self.enable_suspicious_detection = global_setting
        object.__setattr__(self, "_inherits_suspicious_detection", True)

    def __setattr__(self, name: str, value: object) -> None:
        if name == "time_restrictions" and value:  # empty means no restriction
            from guard_core.sync.decorators._route_arguments import (
                time_restriction_problems,
            )

            problems = time_restriction_problems(value)
            if problems:
                raise ValueError(" ".join(problems))
        self.store_attribute(name, value)

    def store_attribute(self, name: str, value: object) -> None:
        value = _wrap_in_tracked_container(name, value, self._revision)
        object.__setattr__(self, name, value)
        if name == "enable_suspicious_detection":
            object.__setattr__(self, "_inherits_suspicious_detection", False)
        if self._initialized and name not in _REVISION_EXEMPT_ATTRS:
            revision = self._revision
            if revision is not None:
                revision.bump()
