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


def test_registered_sync_tree_refuses_cloud_blocking_with_only_aiohttp() -> None:
    message = _run_without(
        ("requests",),
        """
        from guard_core._config_capabilities import register_adapter
        from guard_core import SecurityConfig
        register_adapter("flaskapi-guard", "sync")
        try:
            SecurityConfig(block_cloud_providers={"AWS"})
        except ValueError as error:
            print(json.dumps(str(error)))
        """,
    )
    assert "'requests'" in message
    assert "flaskapi-guard[cloud]" in message


def test_registered_async_tree_accepts_cloud_blocking_with_only_aiohttp() -> None:
    config_kept = _run_without(
        ("requests",),
        """
        from guard_core._config_capabilities import register_adapter
        from guard_core import SecurityConfig
        register_adapter("fastapi-guard", "async")
        print(json.dumps(sorted(SecurityConfig(block_cloud_providers={"AWS"})
                                .block_cloud_providers)))
        """,
    )
    assert config_kept == ["AWS"]


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


def test_the_downloader_follows_the_registered_tree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from guard_core import _config_capabilities

    monkeypatch.setattr(_config_capabilities, "_ADAPTER", None)
    assert _config_capabilities._downloader_modules() == ("aiohttp", "requests")
    _config_capabilities.register_adapter("djapi-guard", "sync")
    assert _config_capabilities._downloader_modules() == ("requests",)
    assert "djapi-guard[geo]" in _config_capabilities._install_hint("geo")
