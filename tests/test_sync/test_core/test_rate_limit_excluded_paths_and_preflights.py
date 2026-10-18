import time
from typing import Any

from guard_core.models import SecurityConfig
from guard_core.sync.core.checks.factory import build_default_pipeline
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
from guard_core.sync.decorators import SecurityDecorator
from guard_core.sync.handlers.ipban_handler import ip_ban_manager
from tests.test_sync.conftest import SyncMockGuardRequest
from tests.test_sync.test_core.conftest import build_middleware

IP = "198.51.100.70"
PREFLIGHT_HEADERS = {
    "Origin": "https://app.example.com",
    "Access-Control-Request-Method": "POST",
}


def _pipeline(**settings: Any) -> SecurityCheckPipeline:
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


def _status(
    pipeline: SecurityCheckPipeline,
    path: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    excluded: bool = False,
) -> int | None:
    request = SyncMockGuardRequest(
        path=path, method=method, headers=headers or {}, client_host=IP
    )
    if excluded:
        request.state.guard_exclusion_scoped = True
    response = pipeline.execute(request)
    return None if response is None else response.status_code


def test_an_excluded_path_never_counts_toward_the_rate_limit() -> None:
    pipeline = _pipeline()

    health = [_status(pipeline, "/health", excluded=True) for _ in range(6)]
    api = [_status(pipeline, "/api") for _ in range(3)]

    assert health == [None] * 6
    assert api == [None, None, 429]


def test_an_excluded_path_still_rejects_a_banned_ip() -> None:
    pipeline = _pipeline()
    ip_ban_manager.banned_ips[IP] = time.time() + 300

    assert _status(pipeline, "/health", excluded=True) == 403


def test_a_cors_preflight_is_never_counted() -> None:
    pipeline = _pipeline()

    preflights = [
        _status(pipeline, "/api", "OPTIONS", PREFLIGHT_HEADERS) for _ in range(5)
    ]
    api = [_status(pipeline, "/api") for _ in range(3)]

    assert preflights == [None] * 5
    assert api == [None, None, 429]


def test_an_options_request_without_the_preflight_header_is_counted() -> None:
    pipeline = _pipeline()

    options = [_status(pipeline, "/api", "OPTIONS") for _ in range(3)]

    assert options == [None, None, 429]


def test_a_banned_ips_preflight_is_still_rejected() -> None:
    pipeline = _pipeline()
    ip_ban_manager.banned_ips[IP] = time.time() + 300

    assert _status(pipeline, "/api", "OPTIONS", PREFLIGHT_HEADERS) == 403
