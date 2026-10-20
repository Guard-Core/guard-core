import asyncio

from guard_core.handlers.suspatterns_handler import sus_patterns_handler
from tests.test_event_attribution import (
    SCRIPT_ATTACK,
    _Agent,
    _bus_events,
    _detection_config,
    _pipeline,
    _request,
)


async def test_two_parallel_requests_from_one_ip_inside_100_ms_carry_two_ids() -> None:
    config = _detection_config(enable_ip_banning=False)
    pipeline, middleware = _pipeline(config)
    agent = _Agent()
    sus_patterns_handler.agent_handler = agent

    await asyncio.gather(
        pipeline.execute(_request(path="/a", query_params={"q": SCRIPT_ATTACK})),
        pipeline.execute(_request(path="/b", query_params={"q": SCRIPT_ATTACK})),
    )

    penetrations = _bus_events(middleware, "penetration_attempt")
    detected = [e for e in agent.events if e.event_type == "pattern_detected"]
    ids = {event["correlation_id"] for event in penetrations}
    assert len(penetrations) == len(detected) == 2
    assert len(ids) == 2
    assert {e.metadata["correlation_id"] for e in detected} == ids
    by_endpoint = {e.endpoint: e.metadata["correlation_id"] for e in detected}
    assert {
        e["correlation_id"] for e in penetrations if e["request"].url_path == "/a"
    } == {by_endpoint["/a"]}
