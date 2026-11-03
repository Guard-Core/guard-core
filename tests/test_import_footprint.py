import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

_CONFIG_CHAIN = {
    "async": (
        "from guard_core.models import SecurityConfig\n"
        "from guard_core.core.responses.factory import ErrorResponseFactory\n"
    ),
    "sync": (
        "from guard_core.models import SecurityConfig\n"
        "from guard_core.sync.core.responses.factory import ErrorResponseFactory\n"
    ),
}


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


@pytest.mark.parametrize("tree", ["async", "sync"])
def test_building_a_config_through_the_response_factory_does_not_load_redis(
    tree: str,
) -> None:
    code = (
        "import sys\n"
        + _CONFIG_CHAIN[tree]
        + "SecurityConfig(enable_redis=False)\n"
        + "print('redis' in sys.modules, 'redis.asyncio' in sys.modules)\n"
    )

    assert _fresh(code) == "False False"


def test_the_redis_exception_names_resolve_on_first_read_to_the_redis_classes() -> None:
    code = (
        "import guard_core._redis_exceptions as m\n"
        "import sys\n"
        "before = 'redis' in sys.modules\n"
        "m.RedisError\n"
        "after = 'redis' in sys.modules\n"
        "import redis.exceptions as r\n"
        "same = [m.NoScriptError is r.NoScriptError,\n"
        "        m.RedisConnectionError is r.ConnectionError,\n"
        "        m.RedisError is r.RedisError,\n"
        "        m.RedisTimeoutError is r.TimeoutError,\n"
        "        m.ResponseError is r.ResponseError]\n"
        "print(before, after, same)\n"
    )

    assert _fresh(code) == "False True [True, True, True, True, True]"


def test_without_redis_the_names_are_stand_in_errors_under_one_base() -> None:
    code = (
        "import sys\n"
        "sys.modules['redis'] = None\n"
        "import guard_core._redis_exceptions as m\n"
        "names = [m.NoScriptError, m.RedisConnectionError, m.RedisTimeoutError,\n"
        "         m.ResponseError]\n"
        "print([issubclass(n, m.RedisError) for n in names],\n"
        "      issubclass(m.RedisError, Exception), m.RedisError.__module__,\n"
        "      m.RedisError is m.RedisError)\n"
    )

    assert (
        _fresh(code)
        == "[True, True, True, True] True guard_core._redis_exceptions True"
    )


def test_a_name_the_module_does_not_export_is_an_attribute_error() -> None:
    code = (
        "import guard_core._redis_exceptions as m\n"
        "try:\n"
        "    m.NotAnError\n"
        "except AttributeError as error:\n"
        "    print('missing', error)\n"
    )

    assert _fresh(code) == "missing NotAnError"


def test_scan_unlink_is_still_the_name_the_redis_handlers_export() -> None:
    code = (
        "import inspect\n"
        "import guard_core.handlers._redis_scan_unlink as own\n"
        "import guard_core.handlers.redis_handler as handler\n"
        "import guard_core.sync.handlers._redis_scan_unlink as sync_own\n"
        "import guard_core.sync.handlers.redis_handler as sync_handler\n"
        "print(str(inspect.signature(handler.scan_unlink))\n"
        "      == str(inspect.signature(own.scan_unlink)),\n"
        "      str(inspect.signature(sync_handler.scan_unlink))\n"
        "      == str(inspect.signature(sync_own.scan_unlink)),\n"
        "      own.SCAN_BATCH, handler._SCAN_BATCH, sync_handler._SCAN_BATCH)\n"
    )

    assert _fresh(code) == "True True 500 500 500"
