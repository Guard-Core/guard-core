from typing import Any
from unittest.mock import Mock

import pytest

from guard_core.core.checks.factory import build_default_pipeline
from guard_core.decorators import SecurityDecorator
from guard_core.handlers import ipban_handler
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest
from tests.test_core.conftest import build_middleware

CLIENT = "203.0.113.5"


class _BusWithOnlySendMiddlewareEvent:
    async def send_middleware_event(self, **kwargs: Any) -> None:
        return None

    async def send_cloud_detection_events(self, *args: Any, **kwargs: Any) -> None:
        return None


async def _status(
    fail_secure: bool,
    *,
    requests: int = 1,
    headers: dict[str, str] | None = None,
    query_params: dict[str, str] | None = None,
    country: str | None = None,
    banned: bool = False,
    **settings: Any,
) -> int | None:
    settings.setdefault("enable_penetration_detection", False)
    settings.setdefault("enable_rate_limiting", False)
    if country is not None:
        settings["geo_ip_handler"] = Mock()
    config = SecurityConfig(enable_redis=False, fail_secure=fail_secure, **settings)
    middleware = build_middleware(config, SecurityDecorator(config))
    middleware.event_bus = _BusWithOnlySendMiddlewareEvent()
    if country is not None:
        middleware.geo_ip_handler = Mock()
        middleware.geo_ip_handler.get_country = Mock(return_value=country)
    if banned:
        await ipban_handler.ip_ban_manager.ban_ip(CLIENT, 600, "test")
    pipeline = build_default_pipeline(middleware)
    response = None
    for _ in range(requests):
        request = MockGuardRequest(
            path="/x",
            client_host=CLIENT,
            headers=headers or {"User-Agent": "curl/8.4"},
            query_params=query_params or {},
        )
        response = await pipeline.execute(request)
    return None if response is None else response.status_code


@pytest.mark.parametrize("fail_secure", [True, False])
@pytest.mark.parametrize(
    ("expected", "scenario"),
    [
        (
            403,
            {
                "headers": {"User-Agent": "evilbot/1.0"},
                "blocked_user_agents": ["evilbot"],
            },
        ),
        (403, {"banned": True}),
        (403, {"country": "CN", "blocked_countries": ["CN"]}),
        (
            400,
            {
                "query_params": {"q": "<script>alert(1)</script>"},
                "enable_penetration_detection": True,
            },
        ),
        (
            429,
            {
                "requests": 2,
                "enable_rate_limiting": True,
                "rate_limit": 1,
                "rate_limit_window": 60,
            },
        ),
    ],
    ids=["blocked-user-agent", "banned-ip", "blocked-country", "attack", "rate-limit"],
)
async def test_a_bus_with_only_send_middleware_event_still_blocks(
    fail_secure: bool, expected: int, scenario: dict[str, Any]
) -> None:
    assert await _status(fail_secure, **scenario) == expected
