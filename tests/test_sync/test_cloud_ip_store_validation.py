from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.cloud_ip_stores import InMemoryCloudIpStore
from guard_core.sync.protocols.cloud_ip_store_protocol import SyncCloudIpStoreProtocol


class _DuckTypedStore:
    def get(self, provider: str) -> set[str] | None:
        return None

    def set(self, provider: str, ranges: set[str], ttl: int | None = None) -> None: ...

    def clear(self) -> None: ...


class _MembersFromGetattrStore:
    def __getattr__(self, name: str) -> MagicMock:
        if name in ("get", "set", "clear"):
            return MagicMock()
        raise AttributeError(name)


@pytest.mark.parametrize(
    "store",
    [
        InMemoryCloudIpStore(),
        _DuckTypedStore(),
        _MembersFromGetattrStore(),
        MagicMock(spec=SyncCloudIpStoreProtocol),
        MagicMock(),
    ],
    ids=["real", "duck-typed", "members-from-getattr", "spec-mock", "magic-mock"],
)
def test_cloud_ip_store_with_every_member_is_accepted_on_every_interpreter(
    store: object,
) -> None:
    config = SyncSecurityConfig(enable_redis=False, cloud_ip_store=store)

    assert config.cloud_ip_store is store


def test_cloud_ip_store_factory_is_still_accepted() -> None:
    def factory(redis_handler: object) -> InMemoryCloudIpStore:
        return InMemoryCloudIpStore()

    config = SyncSecurityConfig(enable_redis=False, cloud_ip_store=factory)

    assert config.cloud_ip_store is factory


@pytest.mark.parametrize("value", [object(), "store", 3])
def test_cloud_ip_store_that_is_neither_a_store_nor_a_factory_is_refused(
    value: object,
) -> None:
    with pytest.raises(ValidationError):
        SyncSecurityConfig(enable_redis=False, cloud_ip_store=value)


class _StoreWithoutClear:
    def get(self, provider: str) -> set[str] | None:
        return None

    def set(self, provider: str, ranges: set[str], ttl: int | None = None) -> None: ...


def test_cloud_ip_store_with_a_missing_member_is_refused() -> None:
    with pytest.raises(ValidationError, match="is_instance_of"):
        SyncSecurityConfig(enable_redis=False, cloud_ip_store=_StoreWithoutClear())
