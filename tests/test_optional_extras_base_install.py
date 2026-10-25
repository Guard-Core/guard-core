import json
import subprocess
import sys
import textwrap
from importlib import reload
from typing import Any

import pytest

FOUR = ("redis", "maxminddb", "aiohttp", "requests")


def _run_without(blocked: tuple[str, ...], body: str) -> Any:
    script = (
        "import json, sys, warnings\n"
        "warnings.simplefilter('ignore')\n"
        f"for name in {blocked!r}:\n"
        "    sys.modules[name] = None\n" + textwrap.dedent(body)
    )
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_every_public_name_and_a_default_config_work_without_the_four() -> None:
    names = _run_without(
        FOUR,
        """
        import guard_core, guard_core.sync
        from guard_core import SecurityConfig
        for module in (guard_core, guard_core.sync):
            for name in module.__all__:
                getattr(module, name)
        import guard_core.handlers.redis_handler, guard_core.sync.handlers.redis_handler
        config = SecurityConfig()
        print(json.dumps([config.enable_redis, config.geo_ip_handler is None]))
        """,
    )
    assert names == [False, True]


def test_the_redis_fast_path_modules_import_without_redis_in_both_trees() -> None:
    names = _run_without(
        ("redis",),
        """
        import guard_core.handlers._redis_lean, guard_core.handlers._redis_ban_strike
        import guard_core.sync.handlers._redis_lean
        import guard_core.sync.handlers._redis_ban_strike
        print(json.dumps(sys.modules.get("redis")))
        """,
    )
    assert names is None


def test_a_redis_config_with_an_agent_needs_neither_aiohttp_nor_requests() -> None:
    loaded = _run_without(
        ("maxminddb", "aiohttp", "requests"),
        """
        import asyncio
        from unittest.mock import MagicMock
        from guard_core.core.initialization.handler_initializer import (
            HandlerInitializer,
        )
        from guard_core.models import SecurityConfig
        config = SecurityConfig(
            redis_url="redis://127.0.0.1:1", enable_agent=True, agent_api_key="k"
        )
        initializer = HandlerInitializer(config, agent_handler=MagicMock())
        initializer.composite_handler = MagicMock()
        asyncio.run(initializer.initialize_agent_for_handlers())
        print(json.dumps([m for m in ("aiohttp", "requests") if sys.modules[m]]))
        """,
    )
    assert loaded == []


def test_each_extra_feature_raises_the_construction_error_naming_the_extra() -> None:
    messages = _run_without(
        FOUR,
        """
        from guard_core import SecurityConfig
        out = {}
        for label, kwargs in {
            "redis": dict(enable_redis=True, redis_url="redis://x"),
            "cloud": dict(block_cloud_providers={"AWS"}),
            "geo": dict(blocked_countries={"US"}, ipinfo_token="t"),
        }.items():
            try:
                SecurityConfig(**kwargs)
            except ValueError as error:
                out[label] = str(error)
        print(json.dumps(out))
        """,
    )
    assert "pip install guard-core[redis]" in messages["redis"]
    assert "pip install guard-core[cloud]" in messages["cloud"]
    assert "pip install guard-core[geo]" in messages["geo"]


def test_a_missing_extra_is_refused_on_assignment_copy_and_batch() -> None:
    outcomes = _run_without(
        FOUR,
        """
        from guard_core import SecurityConfig
        from guard_core._security_config_batch import prepare_config_batch
        config = SecurityConfig(enable_redis=False)

        def refused(action):
            try:
                action()
            except ValueError as error:
                return "guard-core[" in str(error)
            return False

        out = {
            "assign_redis": refused(lambda: setattr(config, "redis_url", "redis://x")
                                    or setattr(config, "enable_redis", True)),
            "assign_cloud": refused(
                lambda: setattr(config, "block_cloud_providers", {"AWS"})
            ),
            "assign_geo": refused(lambda: (
                setattr(config, "ipinfo_token", "t"),
                setattr(config, "blocked_countries", {"US"}),
            )),
            "copy_redis": refused(
                lambda: config.model_copy(
                    update={"enable_redis": True, "redis_url": "redis://x"}
                )
            ),
            "copy_cloud": refused(
                lambda: config.model_copy(update={"block_cloud_providers": {"AWS"}})
            ),
            "batch_cloud": refused(
                lambda: prepare_config_batch(
                    config, {"block_cloud_providers": {"AWS"}}, ()
                )
            ),
            "batch_geo": refused(
                lambda: prepare_config_batch(
                    config.model_copy(update={"ipinfo_token": "t"}),
                    {"blocked_countries": {"US"}},
                    (),
                )
            ),
            "state_kept": [config.enable_redis, config.block_cloud_providers],
        }
        print(json.dumps(out, default=list))
        """,
    )
    assert outcomes.pop("state_kept") == [False, None]
    assert outcomes == dict.fromkeys(outcomes, True)


def test_the_redis_exceptions_fall_back_to_local_classes_without_redis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from guard_core import _redis_exceptions

    real_connection_error = _redis_exceptions.RedisConnectionError
    monkeypatch.setitem(sys.modules, "redis.exceptions", None)
    try:
        reload(_redis_exceptions)
        assert _redis_exceptions.RedisConnectionError is not real_connection_error
        assert issubclass(_redis_exceptions.NoScriptError, _redis_exceptions.RedisError)
        assert issubclass(
            _redis_exceptions.RedisTimeoutError, _redis_exceptions.RedisError
        )
    finally:
        monkeypatch.undo()
        reload(_redis_exceptions)
    assert _redis_exceptions.RedisConnectionError is real_connection_error


_TREE_PROBE = """
import asyncio
from guard_core import SecurityConfig
from guard_core.core.initialization.handler_initializer import HandlerInitializer
from guard_core.exceptions import DownloaderNotInstalledError
from guard_core.sync.core.initialization.handler_initializer import (
    HandlerInitializer as SyncHandlerInitializer,
)
from guard_core.sync.handlers.cloud_handler import cloud_handler as sync_cloud


def refused(build):
    try:
        build()
    except DownloaderNotInstalledError as error:
        assert isinstance(error, ValueError)
        return str(error)
    return None


cloud_config = SecurityConfig(block_cloud_providers={"AWS"})
geo_config = SecurityConfig(ipinfo_token="t", blocked_countries={"US"})
out = {
    "sync_cloud": refused(lambda: SyncHandlerInitializer(cloud_config)),
    "async_cloud": refused(lambda: HandlerInitializer(cloud_config)),
    "sync_geo": refused(
        lambda: SyncHandlerInitializer(
            geo_config, geo_ip_handler=geo_config.geo_ip_handler
        )
    ),
    "async_geo": refused(
        lambda: HandlerInitializer(geo_config, geo_ip_handler=geo_config.geo_ip_handler)
    ),
    "named": refused(
        lambda: SyncHandlerInitializer(cloud_config, adapter="flaskapi-guard")
    ),
    "sync_fetch": refused(lambda: sync_cloud.refresh(["AWS"])),
}
print(json.dumps(out))
"""


def test_each_tree_refuses_its_own_missing_downloader_in_one_process() -> None:
    sync_only_aiohttp = _run_without(("requests", "maxminddb_unused"), _TREE_PROBE)
    assert "'requests'" in sync_only_aiohttp["sync_cloud"]
    assert sync_only_aiohttp["async_cloud"] is None
    assert "'requests'" in sync_only_aiohttp["sync_geo"]
    assert sync_only_aiohttp["async_geo"] is None
    assert "flaskapi-guard[cloud]" in sync_only_aiohttp["named"]
    assert "'requests'" in sync_only_aiohttp["sync_fetch"]


def test_the_async_tree_refuses_a_missing_aiohttp_while_the_sync_tree_does_not() -> (
    None
):
    async_only_requests = _run_without(("aiohttp", "maxminddb_unused"), _TREE_PROBE)
    assert "'aiohttp'" in async_only_requests["async_cloud"]
    assert async_only_requests["sync_cloud"] is None
    assert "'aiohttp'" in async_only_requests["async_geo"]
    assert async_only_requests["sync_geo"] is None
    assert async_only_requests["sync_fetch"] is None


def test_the_adapter_name_comes_from_the_registration_for_the_config_message() -> None:
    message = _run_without(
        ("requests", "aiohttp"),
        """
        from guard_core._config_capabilities import register_adapter
        from guard_core import SecurityConfig
        register_adapter("flaskapi-guard")
        try:
            SecurityConfig(block_cloud_providers={"AWS"})
        except ValueError as error:
            print(json.dumps(str(error)))
        """,
    )
    assert "flaskapi-guard[cloud]" in message
