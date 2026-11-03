import time
from collections.abc import Iterator
from typing import Any, cast

from guard_core.core.checks.factory import build_default_pipeline
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.decorators import SecurityDecorator
from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest
from tests.test_core.conftest import build_middleware

IP = "198.51.100.70"
PREFLIGHT_HEADERS = {
    "Origin": "https://app.example.com",
    "Access-Control-Request-Method": "POST",
}


def _pipeline(**settings: object) -> SecurityCheckPipeline:
    defaults: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": True,
        "rate_limit": 2,
        "rate_limit_window": 60,
        "exclude_paths": ["/health"],
    }
    config = SecurityConfig(**{**defaults, **settings})
    return build_default_pipeline(build_middleware(config, SecurityDecorator(config)))


async def _status(
    pipeline: SecurityCheckPipeline,
    path: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    excluded: bool = False,
) -> int | None:
    request = MockGuardRequest(
        path=path, method=method, headers=headers or {}, client_host=IP
    )
    if excluded:
        request.state.guard_exclusion_scoped = True
    response = await pipeline.execute(request)
    return None if response is None else response.status_code


async def test_an_excluded_path_never_counts_toward_the_rate_limit() -> None:
    pipeline = _pipeline()

    health = [await _status(pipeline, "/health", excluded=True) for _ in range(6)]
    api = [await _status(pipeline, "/api") for _ in range(3)]

    assert health == [None] * 6
    assert api == [None, None, 429]


async def test_an_excluded_path_still_rejects_a_banned_ip() -> None:
    pipeline = _pipeline()
    ip_ban_manager.banned_ips[IP] = time.time() + 300

    assert await _status(pipeline, "/health", excluded=True) == 403


async def test_a_cors_preflight_is_never_counted() -> None:
    pipeline = _pipeline()

    preflights = [
        await _status(pipeline, "/api", "OPTIONS", PREFLIGHT_HEADERS) for _ in range(5)
    ]
    api = [await _status(pipeline, "/api") for _ in range(3)]

    assert preflights == [None] * 5
    assert api == [None, None, 429]


async def test_an_options_request_without_the_preflight_header_is_counted() -> None:
    pipeline = _pipeline()

    options = [await _status(pipeline, "/api", "OPTIONS") for _ in range(3)]

    assert options == [None, None, 429]


async def test_a_banned_ips_preflight_is_still_rejected() -> None:
    pipeline = _pipeline()
    ip_ban_manager.banned_ips[IP] = time.time() + 300

    assert await _status(pipeline, "/api", "OPTIONS", PREFLIGHT_HEADERS) == 403


class _TupleIteratingHeaders:
    """Like werkzeug's Headers: iterating gives pairs, keys() gives the names."""

    def __init__(self, headers: dict[str, str]) -> None:
        self._headers = headers

    def __iter__(self) -> Iterator[tuple[str, str]]:
        return iter(self._headers.items())

    def keys(self) -> list[str]:
        return list(self._headers)

    def get(self, name: str, default: str | None = None) -> str | None:
        return self._headers.get(name, default)


async def test_a_preflight_is_recognized_when_headers_iterate_as_pairs() -> None:
    pipeline = _pipeline()

    for _ in range(4):
        request = MockGuardRequest(
            path="/api",
            method="OPTIONS",
            client_host=IP,
            headers=cast(dict[str, str], _TupleIteratingHeaders(PREFLIGHT_HEADERS)),
        )
        assert await pipeline.execute(request) is None

    assert [await _status(pipeline, "/api") for _ in range(3)] == [None, None, 429]
