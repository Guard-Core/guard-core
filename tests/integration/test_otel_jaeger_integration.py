import asyncio
import os
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

import aiohttp
import pytest

if TYPE_CHECKING:
    from testcontainers.core.container import DockerContainer

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("INTEGRATION_TESTS") != "1",
        reason="Integration tests require INTEGRATION_TESTS=1 and Docker",
    ),
]


@pytest.fixture(scope="module")
def jaeger_container() -> Iterator["DockerContainer"]:
    from testcontainers.core.container import DockerContainer
    from testcontainers.core.wait_strategies import LogMessageWaitStrategy

    container = (
        DockerContainer("jaegertracing/all-in-one:1.76.0")
        .with_env("COLLECTOR_OTLP_ENABLED", "true")
        .with_exposed_ports(16686, 4318)
        .waiting_for(
            LogMessageWaitStrategy("Starting HTTP server").with_startup_timeout(60)
        )
    )
    container.start()
    yield container
    container.stop()


@pytest.fixture
def jaeger_otlp_endpoint(jaeger_container: "DockerContainer") -> str:
    host = jaeger_container.get_container_host_ip()
    port = jaeger_container.get_exposed_port(4318)
    return f"http://{host}:{port}"


@pytest.fixture
def jaeger_ui_url(jaeger_container: "DockerContainer") -> str:
    host = jaeger_container.get_container_host_ip()
    port = jaeger_container.get_exposed_port(16686)
    return f"http://{host}:{port}"


class _SyntheticEvent:
    def __init__(
        self,
        event_type: str,
        ip_address: str,
        action_taken: str,
        reason: str,
        endpoint: str,
        method: str,
        status_code: int,
        metadata: dict[str, Any],
    ) -> None:
        self.event_type = event_type
        self.ip_address = ip_address
        self.action_taken = action_taken
        self.reason = reason
        self.endpoint = endpoint
        self.method = method
        self.status_code = status_code
        self.metadata = metadata


async def _wait_for_service(ui_url: str, service_name: str) -> None:
    timeout = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession() as session:
        for _ in range(10):
            async with session.get(
                f"{ui_url}/api/services", timeout=timeout
            ) as response:
                payload = await response.json()
            services = payload.get("data") or []
            if service_name in services:
                return
            await asyncio.sleep(1)
        raise AssertionError(
            f"Jaeger did not register service '{service_name}' within 10s"
        )


async def _fetch_penetration_spans(
    ui_url: str, service_name: str
) -> list[dict[str, Any]]:
    timeout = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession() as session:
        params = {"service": service_name, "limit": "10", "lookback": "5m"}
        async with session.get(
            f"{ui_url}/api/traces", params=params, timeout=timeout
        ) as response:
            payload = await response.json()
    data = payload.get("data") or []
    tags_by_span = [
        {tag["key"]: tag.get("value") for tag in span.get("tags", [])}
        for trace in data
        for span in trace.get("spans", [])
    ]
    return [
        tags
        for tags in tags_by_span
        if tags.get("guard.event_type") == "penetration_attempt"
    ]


async def test_otel_spans_land_with_normalized_endpoint(
    jaeger_otlp_endpoint: str, jaeger_ui_url: str
) -> None:
    from guard_core.core.events.otel_handler import OtelHandler
    from guard_core.models import SecurityConfig

    config = SecurityConfig(
        enable_otel=True,
        otel_service_name="guard-core-integration",
        otel_exporter_endpoint=jaeger_otlp_endpoint,
        otel_resource_attributes={"deployment.environment": "integration"},
    )
    handler = OtelHandler(config)
    await handler.start()

    event = _SyntheticEvent(
        event_type="penetration_attempt",
        ip_address="10.0.0.42",
        action_taken="blocked",
        reason="integration-test-synthetic",
        endpoint="/login",
        method="POST",
        status_code=403,
        metadata={
            "guard.project_id": "proj_test",
            "guard.service.name": "guard-core-integration",
            "guard.threat_score": 90,
        },
    )
    await handler.send_event(event)
    await asyncio.sleep(2)
    await handler.stop()

    await _wait_for_service(jaeger_ui_url, "guard-core-integration")
    spans = await _fetch_penetration_spans(jaeger_ui_url, "guard-core-integration")

    assert spans, "penetration_attempt span not found in Jaeger"
    first = spans[0]
    assert first["guard.ip_address"] == "10.0.0.42"
    assert first["guard.reason"] == "integration-test-synthetic"
    assert first["guard.project_id"] == "proj_test"
    assert first["guard.threat_score"] == 90
