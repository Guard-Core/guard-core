import logging
from unittest.mock import AsyncMock, MagicMock, patch

from guard_core.core.responses.context import ResponseContext
from guard_core.core.responses.factory import ErrorResponseFactory
from guard_core.handlers.behavior_handler import BehaviorRule
from guard_core.models import BehaviorRuleConfig, SecurityConfig
from tests.conftest import MockGuardRequest, MockGuardResponse, MockGuardResponseFactory


def _make_factory(config: SecurityConfig) -> ErrorResponseFactory:
    metrics = MagicMock()
    metrics.collect_request_metrics = AsyncMock()
    ctx = ResponseContext(
        config=config,
        logger=logging.getLogger("test_factory_global"),
        metrics_collector=metrics,
        response_factory=MockGuardResponseFactory(),
    )
    return ErrorResponseFactory(ctx)


async def test_factory_dispatches_global_rules_when_config_has_them() -> None:
    config = SecurityConfig(
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

    async def fake_global(
        request: object,
        response: object,
        client_ip: str | None,
        rules: list[BehaviorRule],
    ) -> None:
        received.append((client_ip, rules))

    request = MockGuardRequest(path="/x")
    response = MockGuardResponse("not found", status_code=404)

    with patch(
        "guard_core.core.responses.factory.extract_client_ip",
        new_callable=AsyncMock,
        return_value="1.2.3.4",
    ):
        await factory.process_response(
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


async def test_factory_skips_global_when_no_rules_configured() -> None:
    factory = _make_factory(SecurityConfig())

    called = False

    async def fake_global(*_args: object, **_kwargs: object) -> None:
        nonlocal called
        called = True

    request = MockGuardRequest(path="/x")
    response = MockGuardResponse("ok", status_code=200)

    await factory.process_response(
        request,
        response,
        0.1,
        None,
        process_global_behavioral_rules=fake_global,
    )
    assert called is False


async def test_factory_skips_global_when_callback_missing() -> None:
    config = SecurityConfig(
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

    request = MockGuardRequest(path="/x")
    response = MockGuardResponse("not found", status_code=404)

    result = await factory.process_response(request, response, 0.1, None)
    assert result is not None
