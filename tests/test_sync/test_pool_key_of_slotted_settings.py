from redis.backoff import ExponentialBackoff
from redis.retry import Retry

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers._redis_shared_clients import (
    _freeze,
    connection_key_of,
    connection_kwargs_of,
    pool_key,
)

URL = "redis://one.invalid:6379/0"


class _Slotted:
    __slots__ = ("count", "_hidden")

    def __init__(self, count: int, hidden: str) -> None:
        self.count = count
        self._hidden = hidden


class _SlottedChild(_Slotted):
    __slots__ = ("__private", "unset")

    def __init__(self, count: int, hidden: str, private: int) -> None:
        super().__init__(count, hidden)
        self.__private = private


class _Mixed:
    __slots__ = ("slot", "__dict__")

    def __init__(self, slot: int, extra: int) -> None:
        self.slot = slot
        self.extra = extra


def _config(retries: int = 3) -> SyncSecurityConfig:
    return SyncSecurityConfig(
        enable_redis=True,
        redis_url=URL,
        redis_prefix="wp381-slots:",
        redis_retries=retries,
        enable_agent=False,
    )


def test_equal_slotted_objects_freeze_to_equal_keys() -> None:
    first, second = _Slotted(1, "a"), _Slotted(1, "a")

    assert _freeze(first) == _freeze(second)


def test_slotted_objects_that_differ_in_a_slot_freeze_to_different_keys() -> None:
    base, other_count, other_hidden = (
        _Slotted(1, "a"),
        _Slotted(2, "a"),
        _Slotted(1, "b"),
    )

    assert _freeze(base) != _freeze(other_count)
    assert _freeze(base) != _freeze(other_hidden)


def test_the_slots_of_every_class_on_the_mro_count_private_names_included() -> None:
    first, second, third = (
        _SlottedChild(1, "a", 7),
        _SlottedChild(1, "a", 7),
        _SlottedChild(1, "a", 8),
    )

    assert _freeze(first) == _freeze(second)
    assert _freeze(first) != _freeze(third)


def test_a_slot_that_was_never_set_is_left_out_not_an_error() -> None:
    frozen = _freeze(_SlottedChild(1, "a", 7))

    assert "unset" not in repr(frozen)


def test_an_object_with_slots_and_a_dict_freezes_both() -> None:
    base, same, other_dict, other_slot = (
        _Mixed(1, 2),
        _Mixed(1, 2),
        _Mixed(1, 3),
        _Mixed(2, 2),
    )

    assert _freeze(base) == _freeze(same)
    assert _freeze(base) != _freeze(other_dict)
    assert _freeze(base) != _freeze(other_slot)


def test_no_frozen_key_carries_an_address() -> None:
    assert " at 0x" not in repr(_freeze(_Slotted(1, "a")))
    assert " at 0x" not in repr(_freeze(Retry(ExponentialBackoff(), 3)))


def test_equal_retry_settings_of_two_apps_give_one_pool_key() -> None:
    first, second = connection_kwargs_of(_config()), connection_kwargs_of(_config())
    one, other = _config(), _config()

    assert first["retry"] is not second["retry"]
    assert pool_key(URL, 5, 1.0, first, None) == pool_key(URL, 5, 1.0, second, None)
    assert connection_key_of(one) == connection_key_of(other)


def test_different_retry_counts_give_different_pool_keys() -> None:
    assert connection_key_of(_config(3)) != connection_key_of(_config(4))
