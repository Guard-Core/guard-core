import logging
import warnings
from typing import Any

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.decorators import SecurityDecorator
from guard_core.sync.handlers import ipban_handler
from tests.test_sync.test_core.conftest import build_route_pipeline, send_request

BOT_IP = "203.0.113.170"


def _config(**settings: Any) -> SecurityConfig:
    defaults: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
    }
    return SecurityConfig(**{**defaults, **settings})


def _whole_header_verifier(request: Any, credential: str) -> bool:
    return credential.startswith("Bearer ")


def _received(scheme: str, authorization: str) -> list[str]:
    received: list[str] = []

    def verifier(request: Any, credential: str) -> bool:
        received.append(credential)
        return True

    pipeline, _, route_id = build_route_pipeline(
        _config(), lambda d: d.require_auth(scheme, verifier=verifier)
    )
    send_request(
        pipeline, route_id, ip=BOT_IP, headers={"authorization": authorization}
    )
    return received


@pytest.mark.parametrize("scheme", ["Bearer", "BEARER", "bEaReR"])
def test_a_capitalized_bearer_type_hands_the_verifier_only_the_token(
    scheme: str,
) -> None:
    assert _received(scheme, "Bearer tok-1") == ["tok-1"]


def test_a_capitalized_basic_type_hands_the_verifier_only_the_blob() -> None:
    assert _received("Basic", "Basic YWxpY2U6cHc=") == ["YWxpY2U6cHc="]


def test_each_capitalized_type_logs_one_startup_warning_and_no_python_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    decorator = SecurityDecorator(_config())

    def bearer_route() -> None:
        pass

    def basic_route() -> None:
        pass

    def lowercase_route() -> None:
        pass

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            decorator.require_auth("Bearer")(bearer_route)
            decorator.require_auth("BASIC")(basic_route)
            decorator.require_auth("bearer")(lowercase_route)

    messages = [r.getMessage() for r in caplog.records]
    assert len(messages) == 2
    assert "bearer_route" in messages[0] and "type='Bearer'" in messages[0]
    assert "basic_route" in messages[1] and "type='BASIC'" in messages[1]
    assert all("only the credential" in m for m in messages)


def test_a_whole_header_verifier_fails_and_bans_past_the_threshold(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config(auto_ban_threshold=2)
    assert "ban_on_hostile_signals" not in config.model_fields_set
    with caplog.at_level(logging.WARNING, logger="guard_core.sync.decorators"):
        pipeline, _, route_id = build_route_pipeline(
            config, lambda d: d.require_auth("Bearer", verifier=_whole_header_verifier)
        )
    startup = [r.getMessage() for r in caplog.records]
    assert len(startup) == 1 and "only the credential" in startup[0]

    statuses = []
    for _ in range(3):
        response = send_request(
            pipeline, route_id, ip=BOT_IP, headers={"authorization": "Bearer tok-1"}
        )
        statuses.append(response and response.status_code)

    assert statuses[0] == 401
    assert ipban_handler.ip_ban_manager.is_ip_banned(BOT_IP)
