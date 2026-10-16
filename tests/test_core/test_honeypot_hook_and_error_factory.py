from typing import Any
from unittest.mock import AsyncMock

from guard_core.models import SecurityConfig
from tests.conftest import MockGuardResponse
from tests.test_core.conftest import build_route_pipeline, send_request

BOT_IP = "203.0.113.7"
FORM = {
    "content-type": "application/x-www-form-urlencoded",
    "content-length": "6",
}


class _Hook:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(self, request: Any, payload: dict[str, Any]) -> None:
        self.calls.append(payload)


def _config(hook: _Hook, **overrides: Any) -> SecurityConfig:
    settings: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
        "on_block": hook,
    }
    settings.update(overrides)
    return SecurityConfig(**settings)


async def _trap_hit(config: SecurityConfig, *decorators: Any) -> tuple[Any, Any]:
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.honeypot_detection(["hp"]), *decorators
    )
    response = await send_request(
        pipeline,
        route_id,
        ip=BOT_IP,
        method="POST",
        headers=FORM,
        body=b"hp=bot",
    )
    return response, middleware


async def test_honeypot_hit_fires_the_block_hook_once_as_honeypot() -> None:
    hook = _Hook()

    response, _ = await _trap_hit(_config(hook))

    assert response is not None
    assert response.status_code == 403
    assert len(hook.calls) == 1
    payload = hook.calls[0]
    assert payload["check_name"] == "honeypot"
    assert payload["status_code"] == 403
    assert payload["passive_mode"] is False
    assert payload["client_ip"] == BOT_IP
    assert payload["method"] == "POST"
    assert payload["trigger_info"] == "honeypot field filled"


async def test_honeypot_403_goes_through_the_error_factory() -> None:
    hook = _Hook()
    config = _config(hook)
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.honeypot_detection(["hp"])
    )
    middleware.create_error_response = AsyncMock(
        return_value=MockGuardResponse("Custom forbidden page", 403)
    )

    response = await send_request(
        pipeline,
        route_id,
        ip=BOT_IP,
        method="POST",
        headers=FORM,
        body=b"hp=bot",
    )

    assert response is not None
    assert response.body == b"Custom forbidden page"
    middleware.create_error_response.assert_awaited_once_with(
        status_code=403, default_message="Forbidden"
    )


async def test_honeypot_passive_mode_fires_the_hook_without_blocking() -> None:
    hook = _Hook()

    response, middleware = await _trap_hit(_config(hook, passive_mode=True))

    assert response is None
    assert [c["check_name"] for c in hook.calls] == ["honeypot"]
    assert hook.calls[0]["passive_mode"] is True
    assert hook.calls[0]["status_code"] is None
    assert middleware.suspicious_request_counts == {}


async def test_honeypot_without_a_hook_still_blocks() -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
    )

    response, _ = await _trap_hit(config)

    assert response is not None
    assert response.status_code == 403


async def test_other_custom_validators_still_skip_the_block_hook() -> None:
    hook = _Hook()
    config = _config(hook)

    async def reject(request: Any) -> Any:
        return MockGuardResponse("app says no", 418)

    pipeline, _, route_id = build_route_pipeline(
        config, lambda d: d.custom_validation(reject)
    )

    response = await send_request(pipeline, route_id, ip=BOT_IP)

    assert response is not None
    assert response.status_code == 418
    assert response.body == b"app says no"
    assert hook.calls == []
