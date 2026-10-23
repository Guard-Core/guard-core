import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest, declare_route

PROBES = [
    "/cgi-bin/",
    "/actuator",
    "/actuator/env",
    "/docker-compose",
    "/credentials/rotate",
    "/credentials",
    "/CHANGELOG.md",
    "/README.md",
    "/system",
    "/config_dump",
    "/backend/config_dump",
    "/app.js.map",
    "/backup.sql",
    "/dump.sql",
    "/db.sql",
    "/shell.php",
    "/cmd.php",
    "/c99.php",
    "/r57.php",
    "/tools/c99.php",
    "/tools/r57.php",
    "/uploads/shell.php",
    "/files/cmd.php",
    "/wp-content/uploads/2024/cmd.php",
    "/media/x/shell.php",
    "/admin.php",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/app/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/manage.py",
    "/wsgi.py",
    "/app.py",
    "/main.go",
    "/deploy.sh",
    "/backup.sh",
    "/srv/app/settings.py",
    "/app/local_settings.py",
    "/app/config.py",
    "/app/secrets.py",
    "/blog/wp-config.php",
    "/site/configuration.php",
    "/app/config.php",
    "/app/config/database.yml",
    "/api/appsettings.Production.json",
    "/wp-content/themes/default",
    "/language/Swedish${IFS}&&cd${IFS}/tmp",
    "/language/Swedish%24%7BIFS%7D%26%26cd%24%7BIFS%7D/tmp",
    "/page.shtml",
    "/CHANGELOG",
    "/ChangeLog",
    "/CHANGELOG?x=1",
    "/system/cron/cron.txt",
    "/system/error.txt",
    "/wp-content/uploads/",
    "/wp-content/uploads",
    "/wp-content/uploads/2024/shell.php",
    "/blog/wp-content/uploads/x/a.php",
]

ORDINARY_ROUTES = [
    "/language/en",
    "/languages",
    "/en/language",
    "/blog/language/python",
    "/docs/changelog",
    "/changelog",
    "/Changelog",
    "/docs/CHANGELOG",
    "/system/log/",
    "/system/logs/",
    "/docs/README.md",
    "/version",
    "/system/status",
    "/management",
    "/api/management",
    "/app/management/health",
    "/en/inicio.html",
    "/static/app.js.map",
    "/static/bundle.js.map",
    "/assets/main.py",
    "/downloads/setup.sh",
    "/news/index.jsp",
    "/v2/system/version",
    "/api/system/version",
    "/account/credentials",
    "/service/credentials",
    "/wp-content/uploads/2024/a.jpg",
    "/tools/shell.php",
    "/api/cmd.php",
    "/agency/news/c100001/page_a.shtml",
    "/vendor/tool/changelog",
    "/news-site/language/latest",
    "/repo/file/owner/project/main/README.md",
]


def _flagged(path: str, route: str | None = None) -> bool:
    request = SyncMockGuardRequest(path=path)
    if route is not None:
        declare_route(request, route)
    result = detect_penetration_attempt(request, SyncSecurityConfig())
    return result.is_threat


ROUTE_GATED = [
    "/system/log/",
    "/system/logs/",
    "/version",
    "/assets/main.py",
    "/downloads/setup.sh",
    "/news/index.jsp",
    "/tools/shell.php",
    "/api/cmd.php",
    "/agency/news/c100001/page_a.shtml",
]


@pytest.mark.parametrize("path", PROBES)
def test_root_probe_shapes_and_named_probes_stay_flagged(path: str) -> None:
    assert _flagged(path) is True


@pytest.mark.parametrize("path", ORDINARY_ROUTES)
def test_ordinary_application_routes_are_not_probes(path: str) -> None:
    assert _flagged(path, route=path) is False


@pytest.mark.parametrize("path", ROUTE_GATED)
@pytest.mark.parametrize("route", [None, "/{page:path}", "/api/{name}", "/docs"])
def test_a_gated_route_is_a_probe_unless_the_app_declares_it(
    path: str, route: str | None
) -> None:
    assert _flagged(path, route=route) is True


def test_a_wordpress_probe_outside_the_uploads_tree_stays_flagged() -> None:
    assert _flagged("/blog/wp-content/plugins/x/readme.txt") is True
    assert _flagged("/wp-content/uploads/2024/a.jpg") is True
    assert (
        _flagged("/wp-content/uploads/2024/a.jpg", route="/wp-content/uploads/{name}")
        is False
    )


def test_the_nested_extension_builder_matches_at_any_depth() -> None:
    import re

    from guard_core.sync.handlers._suspatterns_sources import (
        _path_only_extension_pattern,
    )

    pattern = re.compile(_path_only_extension_pattern(r"\.(?:py|go)"), re.IGNORECASE)

    assert pattern.search("/a/b/main.go")
    assert pattern.search("/main.py")
    assert not pattern.search("/a/b/main.txt")
