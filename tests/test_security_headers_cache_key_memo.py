import json
from collections.abc import Callable
from typing import Any, NoReturn

import pytest

from guard_core.handlers import _security_headers_cache
from guard_core.handlers.security_headers_handler import SecurityHeadersManager
from guard_core.models import SecurityConfig


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
    real_dumps: Callable[..., str] = json.dumps

    def counting_dumps(value: object, **kwargs: object) -> str:
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
    csp = config.security_headers["csp"]
    assert isinstance(csp, dict)
    sources = csp["default-src"]
    first = manager._generate_cache_key(None, config)

    sources.append("https://cdn.example.com")
    changed = manager._generate_cache_key(None, config)
    sources.pop()
    restored = manager._generate_cache_key(None, config)

    assert changed != first
    assert restored == first


def test_a_config_that_cannot_be_copied_is_serialized_without_a_memo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refusing_deepcopy(value: object) -> NoReturn:
        raise TypeError("not copyable")

    monkeypatch.setattr(_security_headers_cache.copy, "deepcopy", refusing_deepcopy)
    manager = SecurityHeadersManager()
    manager._headers_json_memo = None
    config = _config()

    first = manager._generate_cache_key(None, config)
    second = manager._generate_cache_key(None, config)

    assert manager._headers_json_memo is None
    assert first == second
