import logging

import pytest

from guard_core.decorators.access_control import AccessControlMixin
from guard_core.decorators.advanced import AdvancedMixin
from guard_core.decorators.authentication import AuthenticationMixin
from guard_core.decorators.base import BaseSecurityDecorator
from guard_core.decorators.behavioral import BehavioralMixin
from guard_core.decorators.content_filtering import ContentFilteringMixin
from guard_core.decorators.rate_limiting import RateLimitingMixin
from guard_core.models import VALID_CLOUD_PROVIDERS, SecurityConfig
from guard_core.sync.decorators.access_control import (
    AccessControlMixin as SyncAccessControlMixin,
)
from guard_core.sync.decorators.advanced import AdvancedMixin as SyncAdvancedMixin
from guard_core.sync.decorators.authentication import (
    AuthenticationMixin as SyncAuthenticationMixin,
)
from guard_core.sync.decorators.base import (
    BaseSecurityDecorator as SyncBaseSecurityDecorator,
)
from guard_core.sync.decorators.behavioral import (
    BehavioralMixin as SyncBehavioralMixin,
)
from guard_core.sync.decorators.content_filtering import (
    ContentFilteringMixin as SyncContentFilteringMixin,
)
from guard_core.sync.decorators.rate_limiting import (
    RateLimitingMixin as SyncRateLimitingMixin,
)


class _AsyncComposedDecorator(
    BaseSecurityDecorator,
    AccessControlMixin,
    AdvancedMixin,
    AuthenticationMixin,
    BehavioralMixin,
    ContentFilteringMixin,
    RateLimitingMixin,
):
    pass


class _SyncComposedDecorator(
    SyncBaseSecurityDecorator,
    SyncAccessControlMixin,
    SyncAdvancedMixin,
    SyncAuthenticationMixin,
    SyncBehavioralMixin,
    SyncContentFilteringMixin,
    SyncRateLimitingMixin,
):
    pass


def _async_decorator() -> _AsyncComposedDecorator:
    return _AsyncComposedDecorator(SecurityConfig(enable_redis=False))


def _sync_decorator() -> _SyncComposedDecorator:
    return _SyncComposedDecorator(SecurityConfig(enable_redis=False))


def _sample_func() -> None:
    pass


def _other_sample_func() -> None:
    pass


def _third_sample_func() -> None:
    pass


def _fourth_sample_func() -> None:
    pass


def _fifth_sample_func() -> None:
    pass


async def test_async_block_clouds_default_uses_all_supported() -> None:
    d = _async_decorator()
    decorated = d.block_clouds()(_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert rc.block_cloud_providers == set(VALID_CLOUD_PROVIDERS)


async def test_async_block_clouds_with_valid_list() -> None:
    d = _async_decorator()
    decorated = d.block_clouds(["AWS", "GCP"])(_other_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert rc.block_cloud_providers == {"AWS", "GCP"}


async def test_async_block_clouds_filters_unknown_and_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    d = _async_decorator()
    caplog.set_level(logging.WARNING, logger="guard_core.decorators")
    with pytest.warns(DeprecationWarning, match="ignored unknown cloud providers"):
        decorated = d.block_clouds(["AWS", "Bogus"])(_third_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert rc.block_cloud_providers == {"AWS"}
    assert "ignored unknown cloud providers" in caplog.text
    assert "Bogus" in caplog.text


def test_sync_block_clouds_default_uses_all_supported() -> None:
    d = _sync_decorator()
    decorated = d.block_clouds()(_fourth_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert rc.block_cloud_providers == set(VALID_CLOUD_PROVIDERS)


def test_sync_block_clouds_filters_unknown_and_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    d = _sync_decorator()
    caplog.set_level(logging.WARNING, logger="guard_core.sync.decorators")
    with pytest.warns(DeprecationWarning, match="ignored unknown cloud providers"):
        decorated = d.block_clouds(["AWS", "Bogus"])(_fifth_sample_func)
    rc = d.get_route_config(decorated._guard_route_id)
    assert rc is not None
    assert rc.block_cloud_providers == {"AWS"}
    assert "ignored unknown cloud providers" in caplog.text
