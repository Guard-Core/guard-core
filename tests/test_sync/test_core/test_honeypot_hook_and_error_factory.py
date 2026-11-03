from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_core.models import SyncSecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.decorators import SecurityDecorator
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from tests.test_sync.conftest import MockGuardResponse
from tests.test_sync.test_core.conftest import build_route_pipeline, send_request

BOT_IP = "203.0.113.7"
FORM = {
    "content-type": "application/x-www-form-urlencoded",
    "content-length": "6",
}


class _Hook:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(self, request: SyncGuardRequest, payload: dict[str, Any]) -> None:
        self.calls.append(payload)


def _config(hook: _Hook, **overrides: object) -> SyncSecurityConfig:
    settings: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
        "on_block": hook,
    }
    settings.update(overrides)
    return SyncSecurityConfig(**settings)


def _trap_hit(
    config: SyncSecurityConfig, *decorators: Callable[[SecurityDecorator], object]
) -> tuple[Any, Any]:
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.honeypot_detection(["hp"]), *decorators
    )
    response = send_request(
        pipeline,
        route_id,
        ip=BOT_IP,
        method="POST",
        headers=FORM,
        body=b"hp=bot",
    )
    return response, middleware


def test_honeypot_hit_fires_the_block_hook_once_as_honeypot() -> None:
    hook = _Hook()

    response, _ = _trap_hit(_config(hook))

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


def test_honeypot_403_goes_through_the_error_factory() -> None:
    hook = _Hook()
    config = _config(hook)
    pipeline, middleware, route_id = build_route_pipeline(
        config, lambda d: d.honeypot_detection(["hp"])
    )
    middleware.create_error_response = MagicMock(
        return_value=MockGuardResponse("Custom forbidden page", 403)
    )

    response = send_request(
        pipeline,
        route_id,
        ip=BOT_IP,
        method="POST",
        headers=FORM,
        body=b"hp=bot",
    )

    assert response is not None
    assert response.body == b"Custom forbidden page"
    middleware.create_error_response.assert_called_once_with(
        status_code=403, default_message="Forbidden"
    )


def test_honeypot_passive_mode_fires_the_hook_without_blocking() -> None:
    hook = _Hook()

    response, middleware = _trap_hit(_config(hook, passive_mode=True))

    assert response is None
    assert [c["check_name"] for c in hook.calls] == ["honeypot"]
    assert hook.calls[0]["passive_mode"] is True
    assert hook.calls[0]["status_code"] is None
    assert middleware.suspicious_request_counts == {}


def test_honeypot_without_a_hook_still_blocks() -> None:
    config = SyncSecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
    )

    response, _ = _trap_hit(config)

    assert response is not None
    assert response.status_code == 403


def test_other_custom_validators_still_skip_the_block_hook() -> None:
    hook = _Hook()
    config = _config(hook)

    def reject(request: SyncGuardRequest) -> GuardResponse | None:
        return MockGuardResponse("app says no", 418)

    pipeline, _, route_id = build_route_pipeline(
        config, lambda d: d.custom_validation(reject)
    )

    response = send_request(pipeline, route_id, ip=BOT_IP)

    assert response is not None
    assert response.status_code == 418
    assert response.body == b"app says no"
    assert hook.calls == []


def _trap_hit_before_a_later_validator(
    config: SyncSecurityConfig,
) -> tuple[Any, list[int]]:
    later_calls: list[int] = []

    def later_validator(request: SyncGuardRequest) -> GuardResponse | None:
        later_calls.append(1)
        return MockGuardResponse("later says no", 418)

    pipeline, _, route_id = build_route_pipeline(
        config,
        lambda d: (
            lambda func: d.custom_validation(later_validator)(
                d.honeypot_detection(["hp"])(func)
            )
        ),
    )
    response = send_request(
        pipeline,
        route_id,
        ip=BOT_IP,
        method="POST",
        headers=FORM,
        body=b"hp=bot",
    )
    return response, later_calls


def test_passive_honeypot_hit_keeps_evaluating_later_validators(
    caplog: pytest.LogCaptureFixture,
) -> None:
    hook = _Hook()

    with caplog.at_level("WARNING"):
        response, later_calls = _trap_hit_before_a_later_validator(
            _config(hook, passive_mode=True)
        )

    assert response is None
    assert later_calls == [1]
    assert [c["check_name"] for c in hook.calls] == ["honeypot"]
    failures = [r for r in caplog.records if "Custom validation failed" in r.message]
    assert len(failures) == 2


def test_active_honeypot_hit_stops_before_later_validators() -> None:
    response, later_calls = _trap_hit_before_a_later_validator(_config(_Hook()))

    assert response is not None
    assert response.status_code == 403
    assert later_calls == []
