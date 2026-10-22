import json
from typing import Any

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.handlers import _security_headers_cache
from guard_core.sync.handlers.security_headers_handler import SecurityHeadersManager


def _config(**csp_sources: list[str]) -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
        security_headers={
            "enabled": True,
            "csp": {"default-src": ["'self'"], **csp_sources},
        },
    )


def test_an_unchanged_config_serializes_its_security_headers_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dumps_calls: list[Any] = []
    real_dumps = json.dumps

    def counting_dumps(value: Any, **kwargs: Any) -> str:
        dumps_calls.append(value)
        return real_dumps(value, **kwargs)

    monkeypatch.setattr(_security_headers_cache.json, "dumps", counting_dumps)
    manager = SecurityHeadersManager()
    manager._headers_json_memo = None
    config = _config()

    keys = {manager._generate_cache_key(None, config) for _ in range(5)}

    assert len(keys) == 1
    assert len(dumps_calls) == 1


def test_a_changed_config_gets_a_new_key_and_the_old_one_comes_back() -> None:
    manager = SecurityHeadersManager()
    config = _config()
    assert config.security_headers is not None
    sources = config.security_headers["csp"]["default-src"]
    first = manager._generate_cache_key(None, config)

    sources.append("https://cdn.example.com")
    changed = manager._generate_cache_key(None, config)
    sources.pop()
    restored = manager._generate_cache_key(None, config)

    assert changed != first
    assert restored == first
