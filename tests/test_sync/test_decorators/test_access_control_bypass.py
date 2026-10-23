import logging

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.decorators import get_route_id
from guard_core.sync.decorators.access_control import AccessControlMixin
from guard_core.sync.decorators.access_control import (
    AccessControlMixin as SyncAccessControlMixin,
)
from guard_core.sync.decorators.advanced import AdvancedMixin
from guard_core.sync.decorators.advanced import AdvancedMixin as SyncAdvancedMixin
from guard_core.sync.decorators.authentication import AuthenticationMixin
from guard_core.sync.decorators.authentication import (
    AuthenticationMixin as SyncAuthenticationMixin,
)
from guard_core.sync.decorators.base import BaseSecurityDecorator
from guard_core.sync.decorators.base import (
    BaseSecurityDecorator as SyncBaseSecurityDecorator,
)
from guard_core.sync.decorators.behavioral import BehavioralMixin
from guard_core.sync.decorators.behavioral import (
    BehavioralMixin as SyncBehavioralMixin,
)
from guard_core.sync.decorators.content_filtering import ContentFilteringMixin
from guard_core.sync.decorators.content_filtering import (
    ContentFilteringMixin as SyncContentFilteringMixin,
)
from guard_core.sync.decorators.rate_limiting import RateLimitingMixin
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
    return _AsyncComposedDecorator(SyncSecurityConfig(enable_redis=False))


def _sync_decorator() -> _SyncComposedDecorator:
    return _SyncComposedDecorator(SyncSecurityConfig(enable_redis=False))


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


def _sixth_sample_func() -> None:
    pass


def _seventh_sample_func() -> None:
    pass


def _eighth_sample_func() -> None:
    pass


def _ninth_sample_func() -> None:
    pass


def _tenth_sample_func() -> None:
    pass


def _eleventh_sample_func() -> None:
    pass


def _twelfth_sample_func() -> None:
    pass


def test_async_bypass_with_valid_tokens() -> None:
    d = _async_decorator()
    decorated = d.bypass(["ip", "rate_limit"])(_sample_func)
    rc = d.get_route_config(get_route_id(decorated))
    assert rc is not None
    assert rc.bypassed_checks == {"ip", "rate_limit"}


def test_async_bypass_filters_unknown_and_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    d = _async_decorator()
    caplog.set_level(logging.WARNING, logger="guard_core.sync.decorators")
    decorated = d.bypass(["ip", "geo_check"])(_other_sample_func)
    rc = d.get_route_config(get_route_id(decorated))
    assert rc is not None
    assert rc.bypassed_checks == {"ip"}
    assert "ignored unknown checks" in caplog.text
    assert "geo_check" in caplog.text


def test_async_bypass_all_invalid_yields_empty_and_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    d = _async_decorator()
    caplog.set_level(logging.WARNING, logger="guard_core.sync.decorators")
    decorated = d.bypass(["countries", "geo_check"])(_third_sample_func)
    rc = d.get_route_config(get_route_id(decorated))
    assert rc is not None
    assert rc.bypassed_checks == set()
    assert "ignored unknown checks" in caplog.text
    assert "['countries', 'geo_check']" in caplog.text
    assert len(caplog.records) == 1


def test_sync_bypass_with_valid_tokens() -> None:
    d = _sync_decorator()
    decorated = d.bypass(["ip", "rate_limit"])(_fourth_sample_func)
    rc = d.get_route_config(get_route_id(decorated))
    assert rc is not None
    assert rc.bypassed_checks == {"ip", "rate_limit"}


def test_sync_bypass_filters_unknown_and_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    d = _sync_decorator()
    caplog.set_level(logging.WARNING, logger="guard_core.sync.decorators")
    decorated = d.bypass(["ip", "geo_check"])(_fifth_sample_func)
    rc = d.get_route_config(get_route_id(decorated))
    assert rc is not None
    assert rc.bypassed_checks == {"ip"}
    assert "ignored unknown checks" in caplog.text
    assert "geo_check" in caplog.text


def test_sync_bypass_all_invalid_yields_empty_and_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    d = _sync_decorator()
    caplog.set_level(logging.WARNING, logger="guard_core.sync.decorators")
    decorated = d.bypass(["countries", "geo_check"])(_sixth_sample_func)
    rc = d.get_route_config(get_route_id(decorated))
    assert rc is not None
    assert rc.bypassed_checks == set()
    assert "ignored unknown checks" in caplog.text
    assert "['countries', 'geo_check']" in caplog.text
    assert len(caplog.records) == 1


def test_async_bypass_filters_non_string_token_without_raising(
    caplog: pytest.LogCaptureFixture,
) -> None:
    d = _async_decorator()
    caplog.set_level(logging.WARNING, logger="guard_core.sync.decorators")
    decorated = d.bypass(["ip", "geo_check", 123])(_seventh_sample_func)  # type: ignore[list-item]
    rc = d.get_route_config(get_route_id(decorated))
    assert rc is not None
    assert rc.bypassed_checks == {"ip"}
    assert "ignored unknown checks" in caplog.text
    assert "geo_check" in caplog.text
    assert "123" in caplog.text


def test_async_bypass_empty_list_is_noop(
    caplog: pytest.LogCaptureFixture,
) -> None:
    d = _async_decorator()
    caplog.set_level(logging.WARNING, logger="guard_core.sync.decorators")
    decorated = d.bypass([])(_eighth_sample_func)
    rc = d.get_route_config(get_route_id(decorated))
    assert rc is not None
    assert rc.bypassed_checks == set()
    assert not caplog.records


def test_async_bypass_duplicate_tokens_dedupe_without_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    d = _async_decorator()
    caplog.set_level(logging.WARNING, logger="guard_core.sync.decorators")
    decorated = d.bypass(["ip", "ip"])(_ninth_sample_func)
    rc = d.get_route_config(get_route_id(decorated))
    assert rc is not None
    assert rc.bypassed_checks == {"ip"}
    assert not caplog.records


def test_sync_bypass_filters_non_string_token_without_raising(
    caplog: pytest.LogCaptureFixture,
) -> None:
    d = _sync_decorator()
    caplog.set_level(logging.WARNING, logger="guard_core.sync.decorators")
    decorated = d.bypass(["ip", "geo_check", 123])(_tenth_sample_func)  # type: ignore[list-item]
    rc = d.get_route_config(get_route_id(decorated))
    assert rc is not None
    assert rc.bypassed_checks == {"ip"}
    assert "ignored unknown checks" in caplog.text
    assert "geo_check" in caplog.text
    assert "123" in caplog.text


def test_sync_bypass_empty_list_is_noop(
    caplog: pytest.LogCaptureFixture,
) -> None:
    d = _sync_decorator()
    caplog.set_level(logging.WARNING, logger="guard_core.sync.decorators")
    decorated = d.bypass([])(_eleventh_sample_func)
    rc = d.get_route_config(get_route_id(decorated))
    assert rc is not None
    assert rc.bypassed_checks == set()
    assert not caplog.records


def test_sync_bypass_duplicate_tokens_dedupe_without_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    d = _sync_decorator()
    caplog.set_level(logging.WARNING, logger="guard_core.sync.decorators")
    decorated = d.bypass(["ip", "ip"])(_twelfth_sample_func)
    rc = d.get_route_config(get_route_id(decorated))
    assert rc is not None
    assert rc.bypassed_checks == {"ip"}
    assert not caplog.records
