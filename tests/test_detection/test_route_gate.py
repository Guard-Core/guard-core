import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core._utils.route_gate import normalized_last_segment
from guard_core.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest, declare_route

CLIENT = "203.0.113.30"


async def _flagged(path: str, template: str | None = None, **state: Any) -> bool:
    request = MockGuardRequest(path=path)
    if template is not None:
        declare_route(request, template)
    for name, value in state.items():
        setattr(request.state, name, value)
    result = await detect_penetration_attempt(
        request, SecurityConfig(enable_redis=False)
    )
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
async def test_a_path_the_app_declares_as_a_route_is_not_a_probe(
    path: str, template: str
) -> None:
    assert await _flagged(path, template) is False


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
async def test_without_its_own_route_a_gated_path_is_flagged_as_in_v440(
    path: str, template: str | None
) -> None:
    assert await _flagged(path, template) is True


async def test_an_unresolved_route_is_flagged_even_with_a_template_on_the_state() -> (
    None
):
    assert (
        await _flagged("/shop/cart.php", "/shop/cart.php", guard_route_unresolved=True)
        is True
    )


async def test_a_template_that_is_not_text_gives_no_route_knowledge() -> None:
    assert await _flagged("/shop/cart.php", None, guard_route_template=42) is True


def _check(template: Any) -> tuple[SuspiciousActivityCheck, MagicMock, MagicMock]:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=True)
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("test_route_gate")
    middleware.suspicious_request_counts = {}
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(
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


def _stamped(path: str) -> MockGuardRequest:
    request = MockGuardRequest(path=path)
    request.state.client_ip = CLIENT
    request.state.route_config = None
    return request


async def test_an_adapter_that_resolves_routes_late_is_asked_for_a_gated_path() -> None:
    check, _, lookup = _check("/shop/cart.php")

    assert await check.check(_stamped("/shop/cart.php")) is None
    lookup.assert_called_once_with("/shop/cart.php")


async def test_a_late_template_without_the_extension_leaves_the_path_flagged() -> None:
    check, _, lookup = _check("/{path:path}")

    response = await check.check(_stamped("/shop/cart.php"))

    assert response is not None
    assert response.status_code == 400
    lookup.assert_called_once()


async def test_an_adapter_that_cannot_match_the_path_leaves_it_flagged() -> None:
    check, _, lookup = _check(None)
    request = _stamped("/shop/cart.php")

    response = await check.check(request)

    assert response is not None
    assert response.status_code == 400
    lookup.assert_called_once()
    assert getattr(request.state, "guard_route_template", None) is None


async def test_the_prefilter_never_asks_for_an_ordinary_path() -> None:
    check, _, lookup = _check("/api/items")

    assert await check.check(_stamped("/api/items")) is None
    lookup.assert_not_called()


async def test_a_route_the_adapter_already_resolved_is_not_asked_again() -> None:
    check, _, lookup = _check("/other.php")
    request = _stamped("/shop/cart.php")
    declare_route(request, "/shop/cart.php")

    assert await check.check(request) is None
    lookup.assert_not_called()


async def test_an_unresolved_route_is_not_asked_for_a_template() -> None:
    check, _, lookup = _check("/shop/cart.php")
    request = _stamped("/shop/cart.php")
    request.state.guard_route_unresolved = True

    response = await check.check(request)

    assert response is not None
    lookup.assert_not_called()


async def test_a_failing_template_lookup_is_logged_and_the_path_stays_flagged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def _boom(path: str) -> str:
        raise RuntimeError("router exploded")

    check, _, _ = _check(_boom)

    with caplog.at_level(logging.ERROR, logger="guard_core"):
        response = await check.check(_stamped("/shop/cart.php"))

    assert response is not None
    assert "route_template failed" in caplog.text


async def test_a_middleware_without_a_template_method_is_judged_as_in_v440() -> None:
    check, middleware, _ = _check(None)
    del middleware.route_template
    middleware.configure_mock(spec=[])

    response = await check.check(_stamped("/shop/cart.php"))

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
async def test_expansion_extension_variants_are_flagged_without_route_knowledge(
    extension: str, trick: str
) -> None:
    path = trick.format(e=extension)
    assert await _flagged(path) is True
    assert await _flagged(path, "/{path:path}") is True


@pytest.mark.parametrize("extension", EXPANSION_EXTENSIONS)
async def test_expansion_extension_is_clean_when_the_app_declares_it(
    extension: str,
) -> None:
    template = f"/shop/a.{extension}"
    assert await _flagged(f"/shop/a.{extension}", template) is False


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
async def test_a_parameter_named_like_a_probe_token_does_not_declare_it(
    path: str, template: str
) -> None:
    assert await _flagged(path, template) is True


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
async def test_a_literal_next_to_a_parameter_still_declares_the_probe_token(
    path: str, template: str
) -> None:
    assert await _flagged(path, template) is False


def _static_check(
    served: Any,
) -> tuple[SuspiciousActivityCheck, MagicMock]:
    check, middleware, _ = _check(None)
    lookup = AsyncMock(side_effect=served if callable(served) else None)
    if not callable(served):
        lookup.return_value = served
    middleware.static_file_exists = lookup
    return check, lookup


STATIC_CLEAN_PATHS = (
    "/hls/live/segment_001.ts",
    "/static/js/app.4f3a.js.map",
    "/hls/live/SEGMENT_001.TS",
    "/static/js/app.js.MAP",
    "/hls/live/segment_001.ts;jsessionid=1",
)


@pytest.mark.parametrize("path", STATIC_CLEAN_PATHS)
async def test_a_ts_or_map_file_that_exists_in_a_static_mount_is_clean(
    path: str,
) -> None:
    check, lookup = _static_check(True)

    assert await check.check(_stamped(path)) is None
    lookup.assert_awaited_once_with(path)


@pytest.mark.parametrize("path", STATIC_CLEAN_PATHS)
async def test_a_ts_or_map_file_that_is_missing_from_the_mount_is_flagged(
    path: str,
) -> None:
    check, lookup = _static_check(False)

    response = await check.check(_stamped(path))

    assert response is not None
    assert response.status_code == 400
    lookup.assert_awaited_once()


@pytest.mark.parametrize(
    "path",
    [
        "/static/app.py",
        "/static/dump.sql",
        "/static/index.php",
        "/static/Main.java",
        "/static/run.sh",
        "/static/app.tsx",
        "/static/page.jsp",
        "/static/main.go",
    ],
)
async def test_a_source_or_dump_file_is_flagged_even_when_it_exists_in_the_mount(
    path: str,
) -> None:
    check, lookup = _static_check(True)

    response = await check.check(_stamped(path))

    assert response is not None
    lookup.assert_not_awaited()


@pytest.mark.parametrize("path", ["/api/items", "/static/app.js", "/static/a.tsv"])
async def test_the_prefilter_never_asks_the_mount_about_an_ordinary_path(
    path: str,
) -> None:
    check, lookup = _static_check(True)

    assert await check.check(_stamped(path)) is None
    lookup.assert_not_awaited()


async def test_an_existing_static_file_does_not_clear_a_traversal() -> None:
    check, _ = _static_check(True)

    response = await check.check(_stamped("/static/../../etc/passwd"))

    assert response is not None


async def test_an_unresolved_route_is_not_asked_about_a_static_file() -> None:
    check, lookup = _static_check(True)
    request = _stamped("/hls/seg.ts")
    request.state.guard_route_unresolved = True

    response = await check.check(request)

    assert response is not None
    lookup.assert_not_awaited()


async def test_the_answer_is_not_cached_between_requests() -> None:
    check, lookup = _static_check(True)

    assert await check.check(_stamped("/hls/seg.ts")) is None
    lookup.return_value = False
    assert await check.check(_stamped("/hls/seg.ts")) is not None
    assert lookup.await_count == 2


async def test_a_failing_static_lookup_is_logged_and_the_path_stays_flagged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def _boom(path: str) -> bool:
        raise OSError("disk exploded")

    check, _ = _static_check(_boom)

    with caplog.at_level(logging.ERROR, logger="guard_core"):
        response = await check.check(_stamped("/hls/seg.ts"))

    assert response is not None
    assert "static_file_exists failed" in caplog.text


@pytest.mark.parametrize("answer", [None, "yes", 1])
async def test_only_true_counts_as_an_existing_static_file(answer: Any) -> None:
    check, _ = _static_check(answer)

    assert await check.check(_stamped("/hls/seg.ts")) is not None


async def test_an_adapter_without_static_knowledge_is_judged_as_in_v440() -> None:
    check, middleware, _ = _check(None)
    del middleware.static_file_exists

    assert await check.check(_stamped("/hls/seg.ts")) is not None


async def test_an_existing_static_file_does_not_clear_a_query_attack() -> None:
    check, _ = _static_check(True)
    request = MockGuardRequest(
        path="/hls/seg.ts", query_params={"next": "<script>alert(1)</script>"}
    )
    request.state.client_ip = CLIENT
    request.state.route_config = None

    response = await check.check(request)

    assert response is not None


@pytest.mark.parametrize(
    ("path", "segment"),
    [
        ("/a/b/C.PHP;x=1?q=2", "c.php"),
        ("a\\b\\c.php/", "c.php"),
        ("/a/b\\c.php//", "c.php"),
        ("/", ""),
        ("", ""),
        ("c.php", "c.php"),
        ("/hls/seg.ts;jsessionid=1", "seg.ts"),
    ],
)
def test_the_last_segment_is_what_follows_the_last_separator(
    path: str, segment: str
) -> None:
    assert normalized_last_segment(path) == segment
