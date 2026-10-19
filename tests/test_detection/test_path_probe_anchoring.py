import pytest

from guard_core.models import SecurityConfig
from guard_core.utils import detect_penetration_attempt
from tests.conftest import MockGuardRequest

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
]

ORDINARY_ROUTES = [
    "/language/en",
    "/languages",
    "/en/language",
    "/blog/language/python",
    "/docs/changelog",
    "/changelog",
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
    "/gov/csrc/news/c101975/zfxxgk_zdgk.shtml",
    "/claude/code/changelog",
    "/chinadaily/language/thelatest",
    "/github/file/DIYgod/RSSHub/master/README.md",
]


async def _flagged(path: str) -> bool:
    result = await detect_penetration_attempt(
        MockGuardRequest(path=path), SecurityConfig()
    )
    return result.is_threat


@pytest.mark.parametrize("path", PROBES)
async def test_root_probe_shapes_and_named_probes_stay_flagged(path: str) -> None:
    assert await _flagged(path) is True


@pytest.mark.parametrize("path", ORDINARY_ROUTES)
async def test_ordinary_application_routes_are_not_probes(path: str) -> None:
    assert await _flagged(path) is False


async def test_a_wordpress_probe_outside_the_uploads_tree_stays_flagged() -> None:
    assert await _flagged("/blog/wp-content/plugins/x/readme.txt") is True
    assert await _flagged("/wp-content/uploads/") is False
