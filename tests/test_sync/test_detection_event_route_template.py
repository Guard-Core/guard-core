from typing import Protocol, runtime_checkable

from guard_core.models import SyncSecurityConfig
from guard_core.protocols.agent_protocol import JsonValue
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.utils import detect_penetration_attempt
from tests.test_sync.conftest import SyncMockGuardRequest


@runtime_checkable
class _Event(Protocol):
    event_type: str
    metadata: dict[str, object]

    def model_dump(self) -> dict[str, object]: ...


class _Agent:
    def __init__(self) -> None:
        self.events: list[_Event] = []

    def start(self) -> None:
        return None

    def stop(self) -> None:
        return None

    def send_event(self, event: object) -> None:
        assert isinstance(event, _Event)
        self.events.append(event)

    def send_metric(self, _metric: object) -> None:
        return None

    def initialize_redis(self, _redis: object) -> None:
        return None

    def flush_buffer(self) -> None:
        return None

    def get_dynamic_rules(self) -> None:
        return None

    def health_check(self) -> bool:
        return True

    def get_stats(self) -> dict[str, JsonValue]:
        return {}


def _pattern_event(template: str | None) -> _Event:
    config = SyncSecurityConfig(enable_agent=True, agent_api_key="a" * 10)
    agent = _Agent()
    HandlerInitializer(
        config=config, agent_handler=agent
    ).initialize_agent_integrations()
    sus_patterns_handler.configure(config)
    request = SyncMockGuardRequest(
        path="/s/5", query_params={"q": "<script>alert(1)</script>"}
    )
    if template is not None:
        request.state.guard_route_template = template
    result = detect_penetration_attempt(request, config)
    assert result.is_threat is True
    return next(e for e in agent.events if e.event_type == "pattern_detected")


def test_the_detection_event_carries_the_normalised_route_template() -> None:
    event = _pattern_event("/s/(?P<id>[0-9]+)/?")

    assert event.model_dump()["route_template"] == "/s/{id}"
    assert "route_template" not in event.metadata


def test_the_detection_event_of_an_unrouted_request_has_no_template() -> None:
    event = _pattern_event(None)

    assert event.model_dump().get("route_template") is None


def test_outside_a_request_scan_there_is_no_template_to_report() -> None:
    from guard_core.sync._utils.scan_route_template import (
        scanned_request_route_template_fields,
    )

    assert scanned_request_route_template_fields() == {}
