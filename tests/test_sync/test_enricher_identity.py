from types import SimpleNamespace

from guard_core.models import SyncSecurityConfig
from guard_core.sync.core.events.enricher import EnrichmentContext, EventEnricher


def _enricher(cfg: SyncSecurityConfig) -> EventEnricher:
    return EventEnricher(EnrichmentContext(config=cfg))


def test_identity_populates_project_and_service_from_config() -> None:
    cfg = SyncSecurityConfig(
        enable_agent=True,
        agent_api_key="a" * 10,
        agent_project_id="proj-123",
        enable_enrichment=True,
        otel_service_name="api-prod",
    )
    event = SimpleNamespace(event_type="ip_blocked", metadata={})
    _enricher(cfg).enrich_event(event)

    assert event.metadata["guard.project_id"] == "proj-123"
    assert event.metadata["guard.service.name"] == "api-prod"
    assert "guard.deployment.environment" not in event.metadata


def test_identity_adds_deployment_environment_when_set() -> None:
    cfg = SyncSecurityConfig(
        enable_agent=True,
        agent_api_key="a" * 10,
        agent_project_id="proj-9",
        enable_enrichment=True,
        otel_service_name="api",
        otel_resource_attributes={"deployment.environment": "prod"},
    )
    event = SimpleNamespace(event_type="ip_blocked", metadata={})
    _enricher(cfg).enrich_event(event)

    assert event.metadata["guard.deployment.environment"] == "prod"


def test_identity_omits_project_id_when_unset() -> None:
    cfg = SyncSecurityConfig(otel_service_name="svc")
    event = SimpleNamespace(event_type="ip_blocked", metadata={})
    _enricher(cfg).enrich_event(event)

    assert "guard.project_id" not in event.metadata
    assert event.metadata["guard.service.name"] == "svc"


def test_identity_applied_to_metric_tags() -> None:
    cfg = SyncSecurityConfig(
        enable_agent=True,
        agent_api_key="a" * 10,
        agent_project_id="proj-metric",
        enable_enrichment=True,
        otel_service_name="api",
        otel_resource_attributes={"deployment.environment": "staging"},
    )
    metric = SimpleNamespace(metric_type="response_time", tags={"endpoint": "/x"})
    _enricher(cfg).enrich_metric(metric)

    assert metric.tags["endpoint"] == "/x"
    assert metric.tags["guard.project_id"] == "proj-metric"
    assert metric.tags["guard.service.name"] == "api"
    assert metric.tags["guard.deployment.environment"] == "staging"


def test_identity_omits_deployment_env_when_key_missing() -> None:
    cfg = SyncSecurityConfig(
        otel_service_name="svc",
        otel_resource_attributes={"service.version": "1.2.3"},
    )
    event = SimpleNamespace(event_type="ip_blocked", metadata={})
    _enricher(cfg).enrich_event(event)

    assert "guard.deployment.environment" not in event.metadata
