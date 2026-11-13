import json

import pytest
from events_harness import run_events_case
from fixture_types import EventsCaseInput
from run_fixtures import CASES_DIR

_PINNED: dict[str, list[tuple[str, str | None]]] = {
    "evt_route_template_middleware_converter": [("ip_blocked", "/items/{item_id}")],
    "evt_route_template_middleware_angle": [("ip_blocked", "/items/{item_id}")],
    "evt_route_template_middleware_regex": [("ip_blocked", "/orgs/{org}/files/{1}")],
    "evt_route_template_middleware_unnormalizable": [("ip_blocked", None)],
    "evt_route_template_send_agent_event_converter": [
        ("suspicious_request", "/items/{item_id}")
    ],
    "evt_route_template_send_agent_event_regex": [
        ("suspicious_request", "/orgs/{org}/files/{1}")
    ],
    "evt_route_template_rate_limited_converter": [("rate_limited", "/items/{item_id}")],
    "evt_route_template_rate_limited_regex": [
        ("rate_limited", "/orgs/{org}/files/{1}")
    ],
    "evt_route_template_detection_converter": [
        ("pattern_detected", "/items/{item_id}"),
        ("penetration_attempt", "/items/{item_id}"),
    ],
    "evt_route_template_detection_regex": [
        ("pattern_detected", "/orgs/{org}/files/{1}"),
        ("penetration_attempt", "/orgs/{org}/files/{1}"),
    ],
    "evt_route_template_system_event_on_templated_request": [
        ("ip_banned", None),
        ("penetration_attempt", "/items/{item_id}"),
    ],
    "evt_route_template_rate_limited_by_ip": [("rate_limited", None)],
}


def _templated_case(template: str) -> EventsCaseInput:
    return {
        "id": "seam",
        "config": {"blacklist": ["203.0.113.80"]},
        "drives": [
            {
                "client_ip": "203.0.113.80",
                "url_path": "/anything",
                "guard_route_template": template,
            }
        ],
    }


@pytest.mark.parametrize(
    ("raw", "normalized"),
    [
        ("/items/{item_id:int}", "/items/{item_id}"),
        ("/items/<int:item_id>", "/items/{item_id}"),
        (r"^/orgs/(?P<org>[^/]+)/files/(\d+)$", "/orgs/{org}/files/{1}"),
    ],
)
async def test_the_drive_seam_reaches_the_route_template_event_field(
    raw: str, normalized: str
) -> None:
    envelopes = await run_events_case(_templated_case(raw))

    assert [e.get("route_template") for e in envelopes] == [normalized]


def test_the_corpus_pins_the_present_and_the_null_route_template() -> None:
    cases = json.loads((CASES_DIR / "event_stream.json").read_text())["cases"]
    observed = {
        case["id"]: [(e["event_type"], e["route_template"]) for e in case["expected"]]
        for case in cases
        if case["id"].startswith("evt_route_template_")
    }

    assert observed == _PINNED
