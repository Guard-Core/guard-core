import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

_TREES = {"async": "guard_core", "sync": "guard_core.sync"}


def _fresh(code: str) -> str:
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{REPO_ROOT}{os.pathsep}{env.get('PYTHONPATH', '')}"
    return subprocess.run(
        [sys.executable, "-W", "ignore", "-c", code],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    ).stdout.strip()


def _chain(root: str) -> str:
    return (
        "import sys\n"
        "from guard_core.models import SecurityConfig\n"
        f"from {root}.core.responses.factory import ErrorResponseFactory\n"
        f"from {root}.decorators import SecurityDecorator\n"
        "def loaded(*names):\n"
        "    return [n in sys.modules for n in names]\n"
    )


@pytest.mark.parametrize("tree", ["async", "sync"])
def test_the_decorator_argument_checks_load_when_a_decorator_is_applied(
    tree: str,
) -> None:
    root = _TREES[tree]
    code = (
        _chain(root)
        + f"args = '{root}.decorators._route_arguments'\n"
        + f"window = '{root}._utils.time_window'\n"
        + "shared = ['guard_core._geo_source']\n"
        + "before = loaded(args, window)\n"
        + "decorator = SecurityDecorator(SecurityConfig(enable_redis=False))\n"
        + "def route(): ...\n"
        + "decorator.require_ip(whitelist=['203.0.113.0/24'])(route)\n"
        + "decorator.time_window('09:00', '17:00')(route)\n"
        + "decorator.require_auth(type='bearer')(route)\n"
        + "after = loaded(args)\n"
        + "print(before, after)\n"
    )

    assert _fresh(code) == "[False, False] [True]"


@pytest.mark.parametrize("tree", ["async", "sync"])
def test_the_honeypot_helpers_load_when_the_decorator_is_applied(tree: str) -> None:
    root = _TREES[tree]
    code = (
        _chain(root)
        + f"helpers = '{root}._utils.honeypot_fields'\n"
        + "before = loaded(helpers)\n"
        + "decorator = SecurityDecorator(SecurityConfig(enable_redis=False))\n"
        + "def route(): ...\n"
        + "decorator.honeypot_detection(['website'])(route)\n"
        + "print(before, loaded(helpers))\n"
    )

    assert _fresh(code) == "[False] [True]"


@pytest.mark.parametrize("tree", ["async", "sync"])
def test_the_geo_source_check_loads_when_a_country_rule_is_applied(tree: str) -> None:
    root = _TREES[tree]
    code = (
        _chain(root)
        + f"names = ['guard_core._geo_source', '{root}.handlers._downloader']\n"
        + "before = loaded(*names)\n"
        + "decorator = SecurityDecorator(SecurityConfig(enable_redis=False))\n"
        + "def route(): ...\n"
        + "try:\n"
        + "    decorator.block_countries(['US'])(route)\n"
        + "except ValueError as error:\n"
        + "    refusal = str(error).split(' (')[0]\n"
        + "print(before, loaded(*names), refusal)\n"
    )

    assert _fresh(code) == (
        "[False, False] [True, True] "
        "@block_countries declares a country rule but no GeoIP database is configured"
    )


def test_the_emergency_exemption_warning_loads_with_an_emergency_config() -> None:
    code = (
        _chain("guard_core")
        + "name = 'guard_core._emergency_exemptions'\n"
        + "SecurityConfig(enable_redis=False)\n"
        + "before = loaded(name)\n"
        + "SecurityConfig(enable_redis=False, emergency_mode=True)\n"
        + "print(before, loaded(name))\n"
    )

    assert _fresh(code) == "[False] [True]"


def test_the_assignment_checks_load_on_first_assignment_and_stay_exported() -> None:
    code = (
        _chain("guard_core")
        + "name = 'guard_core._security_config_assignment_checks'\n"
        + "import guard_core.models as models\n"
        + "config = SecurityConfig(enable_redis=False)\n"
        + "before = loaded(name)\n"
        + "config.rate_limit = 7\n"
        + "after = loaded(name)\n"
        + "from guard_core import _security_config_assignment_checks as checks\n"
        + "same = all(getattr(models, n) is getattr(checks, n) for n in\n"
        + "           ('changed_copy_fields', 'misconfigurations_now',\n"
        + "            'require_cross_field_rules', 'require_field_constraints'))\n"
        + "namespace = {}\n"
        + "exec('from guard_core.models import *', namespace)\n"
        + "star = all(n in namespace for n in models.__all__)\n"
        + "print(before, after, config.rate_limit, same, star,\n"
        + "      all(n in dir(models) for n in models.__all__))\n"
    )

    assert _fresh(code) == "[False] [True] 7 True True True"


def test_the_assignment_checks_load_on_model_copy() -> None:
    code = (
        _chain("guard_core")
        + "name = 'guard_core._security_config_assignment_checks'\n"
        + "config = SecurityConfig(enable_redis=False)\n"
        + "before = loaded(name)\n"
        + "copied = config.model_copy(update={'rate_limit': 9})\n"
        + "print(before, loaded(name), copied.rate_limit, config.rate_limit)\n"
    )

    assert _fresh(code) == "[False] [True] 9 120"


def test_the_purge_target_check_loads_its_parser_on_first_use() -> None:
    code = (
        _chain("guard_core")
        + "name = 'guard_core.handlers._dynamic_rule_persistence'\n"
        + "from guard_core import _security_config_exempt_purge_validators as v\n"
        + "before = loaded(name)\n"
        + "print(before, v._validate_purge_target(None),\n"
        + "      loaded(name), v._validate_purge_target('rule:3'), loaded(name))\n"
    )

    assert _fresh(code) == "[False] None [False] rule:3 [True]"


def test_the_callable_shape_loads_when_a_slot_adopts_a_callable() -> None:
    code = (
        _chain("guard_core")
        + "name = 'guard_core._callable_shape'\n"
        + "from guard_core.core.callable_slot import CallableSlot\n"
        + "before = loaded(name)\n"
        + "async def modifier(response): return response\n"
        + "slot = CallableSlot('response_modifier')\n"
        + "slot.adopt(modifier)\n"
        + "print(before, loaded(name), slot.invoke is modifier)\n"
    )

    assert _fresh(code) == "[False] [True] True"


_CACHE_CODE = {
    "async": (
        "import asyncio, contextlib\n"
        "from guard_core.handlers.security_headers_handler import (\n"
        "    SecurityHeadersManager,\n"
        ")\n"
        "class Config:\n"
        "    redis_prefix = 'wp412:'\n"
        "class Connection:\n"
        "    def __init__(self):\n"
        "        self.scanned = []\n"
        "    async def scan_iter(self, match, count):\n"
        "        self.scanned.append(match)\n"
        "        for key in ():\n"
        "            yield key\n"
        "class Redis:\n"
        "    config = Config()\n"
        "    connection = Connection()\n"
        "    @contextlib.asynccontextmanager\n"
        "    async def get_connection(self):\n"
        "        yield self.connection\n"
        "run = asyncio.run\n"
    ),
    "sync": (
        "import contextlib\n"
        "from guard_core.sync.handlers.security_headers_handler import (\n"
        "    SecurityHeadersManager,\n"
        ")\n"
        "class Config:\n"
        "    redis_prefix = 'wp412:'\n"
        "class Connection:\n"
        "    def __init__(self):\n"
        "        self.scanned = []\n"
        "    def scan_iter(self, match, count):\n"
        "        self.scanned.append(match)\n"
        "        return iter(())\n"
        "class Redis:\n"
        "    config = Config()\n"
        "    connection = Connection()\n"
        "    @contextlib.contextmanager\n"
        "    def get_connection(self):\n"
        "        yield self.connection\n"
        "def run(value):\n"
        "    return value\n"
    ),
}


@pytest.mark.parametrize("tree", ["async", "sync"])
def test_the_headers_cache_loads_its_record_check_and_scan_when_they_are_used(
    tree: str,
) -> None:
    root = _TREES[tree]
    code = (
        "import sys\n"
        + _CACHE_CODE[tree]
        + "def loaded(*names):\n"
        + "    return [n in sys.modules for n in names]\n"
        + f"scan = '{root}.handlers._redis_scan_unlink'\n"
        + "record = 'guard_core._security_headers_record_validation'\n"
        + "manager = SecurityHeadersManager()\n"
        + "before = loaded(scan, record)\n"
        + "manager._apply_own_state(None, None, None)\n"
        + "middle = loaded(scan, record)\n"
        + "manager.redis_handler = Redis()\n"
        + "run(manager.reset())\n"
        + "print(before, middle, loaded(scan, record),\n"
        + "      Redis.connection.scanned)\n"
    )

    assert _fresh(code) == (
        "[False, False] [False, True] [True, True] ['wp412:security_headers:*']"
    )


@pytest.mark.parametrize("tree", ["async", "sync"])
def test_the_geo_member_call_loads_when_a_database_is_first_loaded(tree: str) -> None:
    root = _TREES[tree]
    handler = (
        "class Handler:\n    calls = []\n    async def initialize(self):\n"
        "        self.calls.append('initialize')\n"
        "import asyncio\nrun = asyncio.run\n"
        if tree == "async"
        else "class Handler:\n    calls = []\n    def initialize(self):\n"
        "        self.calls.append('initialize')\n"
        "def run(value):\n    return value\n"
    )
    code = (
        "import sys\n"
        + handler
        + f"from {root}._utils.access_control import _load_geo_database\n"
        + f"name = '{root}._utils.geo_member_call'\n"
        + "before = name in sys.modules\n"
        + "run(_load_geo_database(Handler()))\n"
        + "print(before, name in sys.modules, Handler.calls)\n"
    )

    assert _fresh(code) == "False True ['initialize']"
