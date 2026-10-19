import logging
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest, declare_route

CLIENT = "203.0.113.30"


def _flagged(path: str, template: str | None = None, **state: Any) -> bool:
    request = SyncMockGuardRequest(path=path)
    if template is not None:
        declare_route(request, template)
    for name, value in state.items():
        setattr(request.state, name, value)
    result = detect_penetration_attempt(request, SecurityConfig(enable_redis=False))
    return result.is_threat


@pytest.mark.parametrize(
    ("path", "template"),
    [
        ("/shop/cart.php", "/shop/cart.php"),
        ("/forum/viewtopic.php", "/forum/viewtopic.php"),
        ("/shop/cart.php", "/shop/{page}.php"),
        ("/shop/CART.PHP", "/shop/cart.php"),
        ("/shop/cart.php/", "/shop/cart.php"),
        ("/shop/cart.php;jsessionid=1", "/shop/cart.php"),
        ("/news/index.jsp", "/news/index.jsp"),
        ("/page.shtml", "/page.shtml"),
        ("/x/y.php", r"/(.*)\.php"),
        ("/x/y.php", r"/(.*)[.]php"),
        ("/x/y.php", r"/(.*).php"),
        ("/system/log/", "/system/log/"),
        ("/system/logs", "/system/logs"),
        ("/version", "/version"),
        ("/api/management", "/api/management/{item}"),
        ("/management", "/management"),
        ("/en/inicio.html", "/en/inicio.html"),
        ("/v2/system/version", "/v2/system/version"),
        ("/blog/language/python", "/blog/language/{name}"),
        ("/docs/README.md", "/docs/README.md"),
        ("/docs/CHANGELOG", "/docs/CHANGELOG"),
        ("/wp-content/uploads/2024/a.jpg", "/wp-content/uploads/{name}"),
        ("/service/credentials", "/service/credentials"),
        ("/system/status", "/system/{name}"),
        ("/wp-admin/about.php", "/wp-admin/{name}.php"),
        ("/wp-admin/", "/wp-admin/{path}"),
        ("/blog/config.php", "/blog/config.php"),
        ("/Controller/Test.php", "/Controller/Test.php"),
        ("/core/CHANGELOG.txt", "/core/CHANGELOG.txt"),
        ("/wp-content/themes/default", "/wp-content/themes/{name}"),
    ],
)
def test_a_path_the_app_declares_as_a_route_is_not_a_probe(
    path: str, template: str
) -> None:
    assert _flagged(path, template) is False


@pytest.mark.parametrize(
    "path",
    [
        "/shop/cart.php",
        "/forum/viewtopic.php",
        "/shop/CART.PHP",
        "/shop/cart.php/",
        "/news/index.jsp",
        "/system/log/",
        "/version",
        "/api/management",
        "/management",
        "/en/inicio.html",
        "/v2/system/version",
        "/blog/language/python",
        "/docs/README.md",
        "/wp-content/uploads/2024/a.jpg",
        "/service/credentials",
        "/system/status",
        "/wp-admin/about.php",
        "/blog/config.php",
        "/Controller/Test.php",
        "/wp-content/themes/default",
    ],
)
@pytest.mark.parametrize(
    "template",
    [None, "/{page:path}", "/<path:filename>", "/api/{name}", "/shop/cart.html", "/"],
)
def test_without_its_own_route_a_gated_path_is_flagged_as_in_v440(
    path: str, template: str | None
) -> None:
    assert _flagged(path, template) is True


def test_an_unresolved_route_is_flagged_even_with_a_template_on_the_state() -> None:
    assert (
        _flagged("/shop/cart.php", "/shop/cart.php", guard_route_unresolved=True)
        is True
    )


def test_a_template_that_is_not_text_gives_no_route_knowledge() -> None:
    assert _flagged("/shop/cart.php", None, guard_route_template=42) is True


def _check(template: Any) -> tuple[SuspiciousActivityCheck, MagicMock, MagicMock]:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=True)
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("test_route_gate")
    middleware.suspicious_request_counts = {}
    middleware.event_bus.send_middleware_event = MagicMock()
    middleware.create_error_response = MagicMock(
        side_effect=lambda status_code, default_message: MagicMock(
            status_code=status_code
        )
    )
    middleware.route_resolver.should_bypass_check = lambda *_: False
    lookup = MagicMock(side_effect=template if callable(template) else None)
    if not callable(template):
        lookup.return_value = template
    middleware.route_template = lookup
    return SuspiciousActivityCheck(middleware), middleware, lookup


def _stamped(path: str) -> SyncMockGuardRequest:
    request = SyncMockGuardRequest(path=path)
    request.state.client_ip = CLIENT
    request.state.route_config = None
    return request


def test_an_adapter_that_resolves_routes_late_is_asked_for_a_gated_path() -> None:
    check, _, lookup = _check("/shop/cart.php")

    assert check.check(_stamped("/shop/cart.php")) is None
    lookup.assert_called_once_with("/shop/cart.php")


def test_a_late_template_without_the_extension_leaves_the_path_flagged() -> None:
    check, _, lookup = _check("/{path:path}")

    response = check.check(_stamped("/shop/cart.php"))

    assert response is not None
    assert response.status_code == 400
    lookup.assert_called_once()


def test_an_adapter_that_cannot_match_the_path_leaves_it_flagged() -> None:
    check, _, lookup = _check(None)
    request = _stamped("/shop/cart.php")

    response = check.check(request)

    assert response is not None
    assert response.status_code == 400
    lookup.assert_called_once()
    assert getattr(request.state, "guard_route_template", None) is None


def test_the_prefilter_never_asks_for_an_ordinary_path() -> None:
    check, _, lookup = _check("/api/items")

    assert check.check(_stamped("/api/items")) is None
    lookup.assert_not_called()


def test_a_route_the_adapter_already_resolved_is_not_asked_again() -> None:
    check, _, lookup = _check("/other.php")
    request = _stamped("/shop/cart.php")
    declare_route(request, "/shop/cart.php")

    assert check.check(request) is None
    lookup.assert_not_called()


def test_an_unresolved_route_is_not_asked_for_a_template() -> None:
    check, _, lookup = _check("/shop/cart.php")
    request = _stamped("/shop/cart.php")
    request.state.guard_route_unresolved = True

    response = check.check(request)

    assert response is not None
    lookup.assert_not_called()


def test_a_failing_template_lookup_is_logged_and_the_path_stays_flagged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def _boom(path: str) -> str:
        raise RuntimeError("router exploded")

    check, _, _ = _check(_boom)

    with caplog.at_level(logging.ERROR, logger="guard_core"):
        response = check.check(_stamped("/shop/cart.php"))

    assert response is not None
    assert "route_template failed" in caplog.text


def test_a_middleware_without_a_template_method_is_judged_as_in_v440() -> None:
    check, middleware, _ = _check(None)
    del middleware.route_template
    middleware.configure_mock(spec=[])

    response = check.check(_stamped("/shop/cart.php"))

    assert response is not None


EXPANSION_EXTENSIONS = (
    "phtml php3 php4 php5 php6 php7 php8 pht phps phar asa cer ashx asmx ascx".split()
)
EXPANSION_TRICKS = (
    "/a.{e}",
    "/a.{e};jsessionid=1",
    "/a.{e}%00.jpg",
    "/a.{e}.",
    "/a.{e}::$DATA",
    "/shop/a.{e}.jpg",
    "/a.{e}.png",
    "/x/y/a.{e}%00",
)


@pytest.mark.parametrize("extension", EXPANSION_EXTENSIONS)
@pytest.mark.parametrize("trick", EXPANSION_TRICKS)
def test_expansion_extension_variants_are_flagged_without_route_knowledge(
    extension: str, trick: str
) -> None:
    path = trick.format(e=extension)
    assert _flagged(path) is True
    assert _flagged(path, "/{path:path}") is True


@pytest.mark.parametrize("extension", EXPANSION_EXTENSIONS)
def test_expansion_extension_is_clean_when_the_app_declares_it(
    extension: str,
) -> None:
    template = f"/shop/a.{extension}"
    assert _flagged(f"/shop/a.{extension}", template) is False


@pytest.mark.parametrize(
    ("path", "template"),
    [
        ("/language/news", "/{language}/news"),
        ("/language/news", "/<language>/news"),
        ("/language/news", "<str:language>/news"),
        ("/language/news", "/(?P<language>[^/]+)/news"),
        ("/version", "/{version}"),
        ("/system/info", "/{system}/info"),
        ("/credentials", "/{credentials}"),
        ("/wp-admin/x", "/{wp-admin}/x"),
        ("/shop/cart.php", "/shop/{cart.php}"),
        ("/shop/cart.php", "/shop/<cart.php>"),
        ("/shop/cart.php", "/{p:path}"),
    ],
)
def test_a_parameter_named_like_a_probe_token_does_not_declare_it(
    path: str, template: str
) -> None:
    assert _flagged(path, template) is True


@pytest.mark.parametrize(
    ("path", "template"),
    [
        ("/shop/cart.php", "/shop/cart.php"),
        ("/shop/cart.php", "/shop/{page}.php"),
        ("/api/version/users", "/api/version/{item}"),
        ("/language/news", "/language/{item}"),
        ("/x/y.php", r"/(.*)\.php"),
        ("/x/y.php", r"/(?P<name>.*)\.php"),
    ],
)
def test_a_literal_next_to_a_parameter_still_declares_the_probe_token(
    path: str, template: str
) -> None:
    assert _flagged(path, template) is False
