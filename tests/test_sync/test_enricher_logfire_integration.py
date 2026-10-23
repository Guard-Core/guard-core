from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from guard_core.models import DynamicRules, SyncSecurityConfig
from guard_core.sync.core.events.enricher import EnrichmentContext, EventEnricher
from guard_core.sync.core.events.logfire_handler import LogfireHandler
from guard_core.sync.handlers.dynamic_rule_handler import DynamicRuleManager


def test_logfire_send_event_forwards_enrichment_metadata() -> None:
    config = SyncSecurityConfig(
        enable_agent=True,
        agent_api_key="a" * 10,
        agent_project_id="proj-log",
        enable_enrichment=True,
        otel_service_name="api-log",
    )
    event = SimpleNamespace(
        event_type="ip_blocked",
        ip_address="1.2.3.4",
        action_taken="blocked",
        reason="test",
        endpoint="/api",
        method="GET",
        status_code=403,
        metadata={
            "guard.project_id": "proj-log",
            "guard.service.name": "api-log",
            "guard.threat_score": 50,
            "guard.rule.id": "rule-42",
            "traceparent": "should-be-excluded",
        },
    )
    with (
        patch("guard_core.sync.core.events.logfire_handler._logfire_available", True),
        patch("guard_core.sync.core.events.logfire_handler.logfire") as mock_logfire,
    ):
        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=None)
        mock_span.__exit__ = MagicMock(return_value=False)
        mock_logfire.span = MagicMock(return_value=mock_span)

        handler = LogfireHandler(config)
        handler.send_event(event)

    mock_logfire.span.assert_called_once()
    _, kwargs = mock_logfire.span.call_args
    assert kwargs["guard.project_id"] == "proj-log"
    assert kwargs["guard.service.name"] == "api-log"
    assert kwargs["guard.threat_score"] == 50
    assert kwargs["guard.rule.id"] == "rule-42"
    assert "traceparent" not in kwargs


def test_logfire_send_event_without_metadata_does_not_crash() -> None:
    config = SyncSecurityConfig()
    event = SimpleNamespace(
        event_type="ip_blocked",
        ip_address="",
        action_taken="",
        reason="",
        endpoint="",
        method="",
        status_code=0,
    )
    with (
        patch("guard_core.sync.core.events.logfire_handler._logfire_available", True),
        patch("guard_core.sync.core.events.logfire_handler.logfire") as mock_logfire,
    ):
        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=None)
        mock_span.__exit__ = MagicMock(return_value=False)
        mock_logfire.span = MagicMock(return_value=mock_span)

        handler = LogfireHandler(config)
        handler.send_event(event)

    mock_logfire.span.assert_called_once()


def test_enricher_to_logfire_end_to_end_through_handler() -> None:
    DynamicRuleManager._instance = None
    config = SyncSecurityConfig(
        enable_agent=True,
        agent_api_key="a" * 10,
        agent_project_id="proj-e2e-log",
        enable_enrichment=True,
        otel_service_name="api-e2e-log",
        otel_resource_attributes={"deployment.environment": "prod"},
    )
    rule_handler = DynamicRuleManager(config)
    rule_handler.current_rules = DynamicRules(
        rule_id="rule-log",
        version=2,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=["1.2.3.4"],
    )
    enricher = EventEnricher(
        EnrichmentContext(config=config, dynamic_rule_handler=rule_handler)
    )

    event = SimpleNamespace(
        event_type="ip_blocked",
        ip_address="1.2.3.4",
        action_taken="blocked",
        reason="test",
        endpoint="/api",
        method="GET",
        status_code=403,
        metadata={},
    )
    enricher.enrich_event(event)

    with (
        patch("guard_core.sync.core.events.logfire_handler._logfire_available", True),
        patch("guard_core.sync.core.events.logfire_handler.logfire") as mock_logfire,
    ):
        mock_span = MagicMock()
        mock_span.__enter__ = MagicMock(return_value=None)
        mock_span.__exit__ = MagicMock(return_value=False)
        mock_logfire.span = MagicMock(return_value=mock_span)

        handler = LogfireHandler(config)
        handler.send_event(event)

    _, kwargs = mock_logfire.span.call_args
    assert kwargs["guard.project_id"] == "proj-e2e-log"
    assert kwargs["guard.service.name"] == "api-e2e-log"
    assert kwargs["guard.deployment.environment"] == "prod"
    assert kwargs["guard.threat_score"] == 50
    assert kwargs["guard.rule.id"] == "rule-log"
    assert kwargs["guard.rule.version"] == 2
