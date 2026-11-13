import logging
import warnings
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_core.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard_core.decorators.base import BaseSecurityDecorator, RouteConfig
from guard_core.decorators.content_filtering import ContentFilteringMixin
from guard_core.exceptions import MisconfigurationError
from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest, declare_route


class _Decorator(BaseSecurityDecorator, ContentFilteringMixin):
    pass


def _route_config(path_params: set[str] | dict[str, set[str]] | None) -> RouteConfig:
    decorator = _Decorator(SecurityConfig(enable_redis=False))

    def target() -> None:
        pass

    decorated = decorator.detection_exclusion(path_params=path_params)(target)
    route_config = decorator.get_route_config(decorator._get_route_id(decorated))
    assert route_config is not None
    return route_config


async def _flagged(
    path: str,
    template: str | None,
    path_params: set[str] | dict[str, set[str]] | None = None,
) -> tuple[bool, str]:
    request = MockGuardRequest(path=path)
    if template is not None:
        declare_route(request, template)
    route_config = _route_config(path_params) if path_params is not None else None
    result = await detect_penetration_attempt(
        request, SecurityConfig(enable_redis=False), route_config
    )
    return result.is_threat, result.trigger_info


RSSHUB_FILE = "/github/file/DIYgod/RSSHub/master/README.md"
RSSHUB_NEWS = "/gov/csrc/news/c101975/zfxxgk_zdgk.shtml"
RSSHUB_LANGUAGE = "/nhentai/index/language/chinese"

SYNTAX_CASES = [
    pytest.param(
        "/github/file/{user}/{repo}/{branch}/{filepath:path}",
        RSSHUB_FILE,
        {"filepath"},
        id="starlette-path-converter",
    ),
    pytest.param(
        "/gov/csrc/news/{suffix:path}",
        RSSHUB_NEWS,
        {"suffix"},
        id="starlette-path-converter-extension",
    ),
    pytest.param(
        "/nhentai/index/{key}/{keyword}",
        RSSHUB_LANGUAGE,
        {"key"},
        id="starlette-segment",
    ),
    pytest.param(
        "/nhentai/index/{key:str}/{keyword:str}",
        RSSHUB_LANGUAGE,
        {"key"},
        id="starlette-segment-with-converter",
    ),
    pytest.param(
        "/github/file/<user>/<repo>/<branch>/<path:filepath>",
        RSSHUB_FILE,
        {"filepath"},
        id="flask-path-converter",
    ),
    pytest.param(
        "/nhentai/index/<key>/<keyword>",
        RSSHUB_LANGUAGE,
        {"key"},
        id="flask-segment",
    ),
    pytest.param(
        "/nhentai/index/<string(length=8):key>/<keyword>",
        RSSHUB_LANGUAGE,
        {"key"},
        id="flask-converter-with-arguments",
    ),
    pytest.param(
        "github/file/<str:user>/<str:repo>/<str:branch>/<path:filepath>",
        RSSHUB_FILE,
        {"filepath"},
        id="django-path-converter",
    ),
    pytest.param(
        "nhentai/index/<str:key>/<str:keyword>",
        RSSHUB_LANGUAGE,
        {"key"},
        id="django-segment",
    ),
    pytest.param(
        "^github/file/(?P<user>[^/]+)/(?P<repo>[^/]+)/(?P<branch>[^/]+)/"
        "(?P<filepath>.*)$",
        RSSHUB_FILE,
        {"filepath"},
        id="django-re_path",
    ),
    pytest.param(
        "/github/file/(?P<user>[^/]+)/(?P<repo>[^/]+)/(?P<branch>[^/]+)/"
        "(?P<filepath>.*)$",
        RSSHUB_FILE,
        {"filepath"},
        id="tornado-named-groups",
    ),
    pytest.param(
        "/nhentai/index/(?P<key>[^/]+)/(?P<keyword>[^/]+)$",
        RSSHUB_LANGUAGE,
        {"key"},
        id="tornado-named-segment",
    ),
    pytest.param(
        "/gov/csrc/news/{suffix:path}",
        RSSHUB_NEWS,
        {"suffix": {"recon"}},
        id="category-map-names-recon",
    ),
]


@pytest.mark.parametrize(("template", "path", "path_params"), SYNTAX_CASES)
async def test_a_probe_token_inside_a_declared_parameter_is_the_apps_own_route(
    template: str, path: str, path_params: set[str] | dict[str, set[str]] | None
) -> None:
    flagged, trigger = await _flagged(path, template, path_params)

    assert flagged is False, trigger


@pytest.mark.parametrize(("template", "path", "path_params"), SYNTAX_CASES)
async def test_the_same_request_with_nothing_declared_is_flagged_as_before(
    template: str, path: str, path_params: set[str] | dict[str, set[str]] | None
) -> None:
    assert (await _flagged(path, template))[0] is True
    assert (await _flagged(path, None))[0] is True


@pytest.mark.parametrize(
    ("template", "path", "path_params"),
    [
        ("/nhentai/index/{key}/{keyword}", RSSHUB_LANGUAGE, {"keyword"}),
        ("/nhentai/index/{key}/{keyword}", "/nhentai/index/chinese/language", {"key"}),
        ("/nhentai/index/{key}/{keyword}", RSSHUB_LANGUAGE, {"recon_is_not_a_name"}),
        ("/system/{item}", "/system/log", {"item"}),
        ("/x/lang{name}", "/x/language", {"name"}),
        ("/files/{name:path}", "/files/a/.git/config", {"name"}),
    ],
)
async def test_a_probe_token_in_a_literal_segment_still_fires(
    template: str, path: str, path_params: set[str] | dict[str, set[str]] | None
) -> None:
    assert (await _flagged(path, template, path_params))[0] is True


@pytest.mark.parametrize(
    ("template", "path"),
    [
        ("/files/{name", "/files/language/x"),
        ("/files/{name}", "/other/language"),
        ("/files/(.*)/(?P<name>.*)", "/other/language/x"),
        ("/files/(.*)/{name}", "/files/language/x"),
        ("/files/(?P<name>(unbalanced", "/files/language"),
        ("/files/{name}/{name}", "/files/a/language"),
    ],
)
async def test_spans_that_cannot_be_computed_declare_nothing(
    template: str, path: str
) -> None:
    assert (await _flagged(path, template, {"name"}))[0] is True


async def test_a_parameter_name_missing_from_the_template_declares_nothing() -> None:
    assert (
        await _flagged(RSSHUB_LANGUAGE, "/nhentai/index/{key}/{keyword}", {"nope"})
    )[0] is True


@pytest.mark.parametrize(
    "path",
    [
        "/files/../../etc/passwd",
        "/files/a/../../../etc/passwd",
        "/files/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/files/%2Fetc%2Fpasswd",
        "/files/a;cat /etc/passwd",
        "/files/a' OR 1=1--",
    ],
)
async def test_value_rules_still_run_on_a_declared_value(path: str) -> None:
    assert (await _flagged(path, "/files/{name:path}", {"name"}))[0] is True
    assert (await _flagged(path, "/files/{name:path}", {"name": {"recon"}}))[0] is True


@pytest.mark.parametrize(
    "path",
    [
        "/files/.env",
        "/files/a/.env",
        "/files/../.env",
        "/files/.git/config",
        "/files/a/.git/config",
        "/files/a/b.sql",
        "/files/a/.htpasswd",
    ],
)
@pytest.mark.parametrize("path_params", [{"name"}, {"name": {"recon"}}])
async def test_sensitive_files_inside_a_declared_value_are_not_excluded(
    path: str, path_params: set[str] | dict[str, set[str]] | None
) -> None:
    assert (await _flagged(path, "/files/{name:path}", path_params))[0] is True


async def test_the_map_form_covers_the_sensitive_file_rows_it_names() -> None:
    template = "/files/{name}"

    assert (await _flagged("/files/shop.php", template, {"name"}))[0] is True
    assert (await _flagged("/files/shop.php", template, {"name": {"sensitive_file"}}))[
        0
    ] is False


async def test_a_value_rule_catches_what_a_category_map_took_off_the_path_rows() -> (
    None
):
    flagged, trigger = await _flagged(
        "/files/a/.env", "/files/{name:path}", {"name": {"sensitive_file"}}
    )

    assert flagged is True
    assert trigger.startswith("Path param 'name'")


async def test_a_declared_value_is_scanned_without_a_path_row_hit() -> None:
    flagged, trigger = await _flagged("/files/ok", "/files/{name}", {"name": {"recon"}})

    assert (flagged, trigger) == (False, "")


def test_path_params_are_validated_like_params() -> None:
    assert _route_config({"a"}).excluded_detection_path_params == {"a"}
    assert _route_config({"a": {"recon"}}).excluded_detection_path_params == {
        "a": {"recon"}
    }
    with pytest.raises(ValueError, match="Unknown detection categories"):
        _route_config({"a": {"nope"}})
    with pytest.raises(ValueError, match="lists no category"):
        _route_config({"a": set()})
    assert RouteConfig().excluded_detection_path_params is None


def _check(config: SecurityConfig) -> SuspiciousActivityCheck:
    middleware = MagicMock()
    middleware.config = config
    middleware.logger = logging.getLogger("test_declared_path_params")
    middleware.suspicious_request_counts = {}
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.route_resolver.should_bypass_check = lambda *_: False
    return SuspiciousActivityCheck(middleware)


def _request(
    template: str, path_params: set[str] | dict[str, set[str]] | None
) -> MockGuardRequest:
    request = MockGuardRequest(path="/docs/index.html")
    declare_route(request, template)
    request.state.client_ip = "203.0.113.31"
    request.state.guard_route_id = "app.docs"
    request.state.route_config = _route_config(path_params)
    return request


async def test_a_root_capture_warns_when_the_flag_is_off(
    caplog: pytest.LogCaptureFixture,
) -> None:
    check = _check(SecurityConfig(enable_redis=False, fail_on_misconfiguration=False))
    request = _request("/{path:path}", {"path"})

    with caplog.at_level(logging.WARNING), warnings.catch_warnings():
        warnings.simplefilter("error")
        assert await check.check(request) is None
        assert await check.check(request) is None

    problems = [r for r in caplog.records if "no literal segment" in r.getMessage()]
    assert len(problems) == 1
    assert "'app.docs'" in problems[0].getMessage()
    assert "'path'" in problems[0].getMessage()


async def test_a_root_capture_refuses_every_request_when_the_flag_is_on() -> None:
    check = _check(SecurityConfig(enable_redis=False, fail_on_misconfiguration=True))
    request = _request("/{path:path}", {"path"})
    errors = []

    for _ in range(3):
        with pytest.raises(MisconfigurationError) as refused:
            await check.check(request)
        errors.append(refused.value)

    assert len({id(error) for error in errors}) == 3
    assert [p.kind for p in errors[0].problems] == [
        "decorator.detection_exclusion.param_without_literal_segment"
    ]


@pytest.mark.parametrize(
    ("template", "path_params"),
    [
        ("/docs/{path:path}", {"path"}),
        ("/docs/<path:path>", {"path"}),
        ("docs/<path:path>", {"path"}),
        (r"^docs/(?P<path>.*)$", {"path"}),
        ("/{tenant}/docs/{path:path}", {"path"}),
        ("/{path:path}", {"unrelated"}),
    ],
)
async def test_a_parameter_with_a_literal_segment_before_it_is_not_reported(
    template: str, path_params: set[str] | dict[str, set[str]] | None
) -> None:
    check = _check(SecurityConfig(enable_redis=False, fail_on_misconfiguration=False))

    assert await check.check(_request(template, path_params)) is None


@pytest.mark.parametrize(
    "template",
    [
        "/<path:path>",
        "/<path>",
        "{path:path}",
        "/(?P<path>.*)",
        "^(?P<path>.*)$",
        "/(?P<tenant>[^/]+)/(?P<path>.*)",
    ],
)
async def test_every_syntax_of_a_root_capture_is_reported(
    template: str, caplog: pytest.LogCaptureFixture
) -> None:
    check = _check(SecurityConfig(enable_redis=False, fail_on_misconfiguration=False))

    with caplog.at_level(logging.WARNING):
        await check.check(_request(template, {"path"}))

    assert [r for r in caplog.records if "'path'" in r.getMessage()]
