import logging
from typing import Any
from unittest.mock import MagicMock, patch

from guard_core.models import BehaviorRuleConfig, SyncSecurityConfig
from guard_core.sync.core.responses.context import ResponseContext
from guard_core.sync.core.responses.factory import ErrorResponseFactory
from guard_core.sync.handlers.behavior_handler import BehaviorRule
from tests.test_sync.conftest import (
    MockGuardResponse,
    MockGuardResponseFactory,
    SyncMockGuardRequest,
)


def _make_factory(config: SyncSecurityConfig) -> ErrorResponseFactory:
    metrics = MagicMock()
    metrics.collect_request_metrics = MagicMock()
    ctx = ResponseContext(
        config=config,
        logger=logging.getLogger("test_factory_global"),
        metrics_collector=metrics,
        response_factory=MockGuardResponseFactory(),
    )
    return ErrorResponseFactory(ctx)


def test_factory_dispatches_global_rules_when_config_has_them() -> None:
    config = SyncSecurityConfig(
        global_behavior_rules=[
            BehaviorRuleConfig(
                rule_type="return_pattern",
                threshold=1,
                pattern="status:404",
                action="log",
            )
        ]
    )
    factory = _make_factory(config)

    received: list[tuple[str | None, list[BehaviorRule]]] = []

    def fake_global(
        request: Any, response: Any, client_ip: str | None, rules: list[BehaviorRule]
    ) -> None:
        received.append((client_ip, rules))

    request = SyncMockGuardRequest(path="/x")
    response = MockGuardResponse("not found", status_code=404)

    with patch(
        "guard_core.sync.core.responses.factory.extract_client_ip",
        return_value="1.2.3.4",
    ):
        factory.process_response(
            request,
            response,
            0.1,
            None,
            process_behavioral_rules=None,
            process_global_behavioral_rules=fake_global,
        )

    assert len(received) == 1
    client_ip, rules = received[0]
    assert client_ip == "1.2.3.4"
    assert len(rules) == 1
    assert rules[0].pattern == "status:404"


def test_factory_skips_global_when_no_rules_configured() -> None:
    factory = _make_factory(SyncSecurityConfig())

    called = False

    def fake_global(*_args: Any, **_kwargs: Any) -> None:
        nonlocal called
        called = True

    request = SyncMockGuardRequest(path="/x")
    response = MockGuardResponse("ok", status_code=200)

    factory.process_response(
        request,
        response,
        0.1,
        None,
        process_global_behavioral_rules=fake_global,
    )
    assert called is False


def test_factory_skips_global_when_callback_missing() -> None:
    config = SyncSecurityConfig(
        global_behavior_rules=[
            BehaviorRuleConfig(
                rule_type="return_pattern",
                threshold=1,
                pattern="status:404",
                action="log",
            )
        ]
    )
    factory = _make_factory(config)

    request = SyncMockGuardRequest(path="/x")
    response = MockGuardResponse("not found", status_code=404)

    result = factory.process_response(request, response, 0.1, None)
    assert result is not None
