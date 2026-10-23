from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import ValidationError

from guard_core.handlers.cloud_ip_stores import InMemoryCloudIpStore
from guard_core.models import SecurityConfig
from guard_core.protocols.cloud_ip_store_protocol import CloudIpStoreProtocol


class _DuckTypedStore:
    async def get(self, provider: str) -> set[str] | None:
        return None

    async def set(
        self, provider: str, ranges: set[str], ttl: int | None = None
    ) -> None: ...

    async def clear(self) -> None: ...


class _MembersFromGetattrStore:
    def __getattr__(self, name: str) -> AsyncMock:
        if name in ("get", "set", "clear"):
            return AsyncMock()
        raise AttributeError(name)


@pytest.mark.parametrize(
    "store",
    [
        InMemoryCloudIpStore(),
        _DuckTypedStore(),
        _MembersFromGetattrStore(),
        MagicMock(spec=CloudIpStoreProtocol),
        MagicMock(),
    ],
    ids=["real", "duck-typed", "members-from-getattr", "spec-mock", "magic-mock"],
)
def test_cloud_ip_store_with_every_member_is_accepted_on_every_interpreter(
    store: object,
) -> None:
    config = SecurityConfig(enable_redis=False, cloud_ip_store=store)

    assert config.cloud_ip_store is store


def test_cloud_ip_store_factory_is_still_accepted() -> None:
    def factory(redis_handler: object) -> InMemoryCloudIpStore:
        return InMemoryCloudIpStore()

    config = SecurityConfig(enable_redis=False, cloud_ip_store=factory)

    assert config.cloud_ip_store is factory


@pytest.mark.parametrize("value", [object(), "store", 3])
def test_cloud_ip_store_that_is_neither_a_store_nor_a_factory_is_refused(
    value: object,
) -> None:
    with pytest.raises(ValidationError):
        SecurityConfig(enable_redis=False, cloud_ip_store=value)


class _StoreWithoutClear:
    async def get(self, provider: str) -> set[str] | None:
        return None

    async def set(
        self, provider: str, ranges: set[str], ttl: int | None = None
    ) -> None: ...


def test_cloud_ip_store_with_a_missing_member_is_refused() -> None:
    with pytest.raises(ValidationError, match="is_instance_of"):
        SecurityConfig(enable_redis=False, cloud_ip_store=_StoreWithoutClear())
