from collections.abc import Callable
from typing import Any, cast

from guard_core.models import SecurityConfig
from guard_core.sync.decorators.base import BaseSecurityDecorator, RouteConfig
from guard_core.sync.decorators.content_filtering import ContentFilteringMixin


class _FakeDecorator(BaseSecurityDecorator, ContentFilteringMixin):
    pass


def _decorate(decorator_fn: Callable[..., Any]) -> Callable[..., Any]:
    def target() -> None:
        pass

    return cast(Callable[..., Any], decorator_fn(target))


def test_route_config_detection_exclusion_defaults_to_none() -> None:
    rc = RouteConfig()
    assert rc.excluded_detection_headers is None
    assert rc.excluded_detection_params is None
    assert rc.excluded_detection_body_fields is None
    assert rc.enabled_detection_categories is None
    assert rc.detection_scan_body is None


def test_detection_exclusion_sets_scan_body() -> None:
    d = _FakeDecorator(SecurityConfig())
    decorated = _decorate(d.detection_exclusion(scan_body=False))
    rc = d.get_route_config(d._get_route_id(decorated))
    assert rc is not None
    assert rc.detection_scan_body is False


def test_detection_exclusion_scan_body_unset_leaves_none() -> None:
    d = _FakeDecorator(SecurityConfig())
    decorated = _decorate(d.detection_exclusion(headers={"authorization"}))
    rc = d.get_route_config(d._get_route_id(decorated))
    assert rc is not None
    assert rc.detection_scan_body is None


def test_route_config_detection_exclusion_accepts_sets() -> None:
    rc = RouteConfig()
    rc.excluded_detection_headers = {"authorization"}
    rc.excluded_detection_params = {"csrf"}
    rc.excluded_detection_body_fields = {"password"}
    rc.enabled_detection_categories = {"xss"}
    assert rc.excluded_detection_headers == {"authorization"}
    assert rc.excluded_detection_params == {"csrf"}
    assert rc.excluded_detection_body_fields == {"password"}
    assert rc.enabled_detection_categories == {"xss"}


def test_detection_exclusion_sets_all_four_fields() -> None:
    d = _FakeDecorator(SecurityConfig())
    decorated = _decorate(
        d.detection_exclusion(
            headers={"authorization"},
            params={"csrf_token"},
            body_fields={"password"},
            categories={"xss", "sqli"},
        )
    )
    route_id = d._get_route_id(decorated)
    rc = d.get_route_config(route_id)
    assert rc is not None
    assert rc.excluded_detection_headers == {"authorization"}
    assert rc.excluded_detection_params == {"csrf_token"}
    assert rc.excluded_detection_body_fields == {"password"}
    assert rc.enabled_detection_categories == {"xss", "sqli"}


def test_detection_exclusion_leaves_unset_args_as_none() -> None:
    d = _FakeDecorator(SecurityConfig())
    decorated = _decorate(d.detection_exclusion(headers={"authorization"}))
    rc = d.get_route_config(d._get_route_id(decorated))
    assert rc is not None
    assert rc.excluded_detection_headers == {"authorization"}
    assert rc.excluded_detection_params is None
    assert rc.excluded_detection_body_fields is None
    assert rc.enabled_detection_categories is None


def test_detection_exclusion_returns_wrapped_callable() -> None:
    d = _FakeDecorator(SecurityConfig())
    decorated = _decorate(d.detection_exclusion(categories={"xss"}))
    assert callable(decorated)
    assert getattr(decorated, "_guard_route_id", None) == d._get_route_id(decorated)


def test_detection_exclusion_no_args_creates_route_config() -> None:
    d = _FakeDecorator(SecurityConfig())
    decorated = _decorate(d.detection_exclusion())
    rc = d.get_route_config(d._get_route_id(decorated))
    assert rc is not None
    assert rc.excluded_detection_headers is None
    assert rc.excluded_detection_params is None
    assert rc.excluded_detection_body_fields is None
    assert rc.enabled_detection_categories is None


def test_detection_exclusion_sets_semantic_headers() -> None:
    d = _FakeDecorator(SecurityConfig())
    decorated = _decorate(d.detection_exclusion(semantic_headers={"cookie"}))
    rc = d.get_route_config(d._get_route_id(decorated))
    assert rc is not None
    assert rc.excluded_semantic_detection_headers == {"cookie"}
    assert rc.excluded_detection_headers is None


def test_semantic_headers_default_to_none() -> None:
    assert RouteConfig().excluded_semantic_detection_headers is None
