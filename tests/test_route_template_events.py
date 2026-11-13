from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_core._utils.agent_events import send_agent_event
from guard_core._utils.route_gate import (
    path_params_without_a_literal_segment_before,
    route_template_event_fields,
)
from guard_core._utils.route_template import capture_groups, normalized_route_template
from guard_core.core.checks.implementations.route_config import RouteConfigCheck
from guard_core.core.events.metrics import MetricsCollector
from guard_core.core.events.middleware_events import SecurityEventBus
from guard_core.models import SecurityConfig
from tests.conftest import MockGuardRequest

_ROUTE_CONFIG = "guard_core.core.checks.implementations.route_config"

NORMALIZED = [
    ("/items/{item_id}", "/items/{item_id}"),
    ("/items/{item_id:int}", "/items/{item_id}"),
    ("/files/{rest:path}", "/files/{rest}"),
    ("/items/<int:item_id>", "/items/{item_id}"),
    ("/items/<item_id>", "/items/{item_id}"),
    ("/files/<any(json, xml):kind>/<string(length=2):code>", "/files/{kind}/{code}"),
    ("files.json", "/files.json"),
    ("orgs/<int:org>/old/(?P<year>[0-9]{4})/$", "/orgs/{org}/old/{year}/"),
    ("/items/(?P<id>[0-9]+)/?", "/items/{id}"),
    ("^items/(?P<id>[0-9]+)/?$", "/items/{id}"),
    (r"/files/(?P<name>[^/]+)\.json$", "/files/{name}.json"),
    (r"/files/(?P<name>[^/]+)\.(?P<ext>json|xml)$", "/files/{name}.{ext}"),
    ("/items/(?P<slug>[a-z]+(?:-[a-z]+)*)$", "/items/{slug}"),
    ("^(?P<a>[a-z]+(?:-[a-z]+)*)/(?P<b>x)$", "/{a}/{b}"),
    (r"/u/([a-z]+)/(\d+)/?", "/u/{0}/{1}"),
    (r"/u/(?P<a>x)/(y)$", "/u/{a}/{1}"),
    (r"/a\-b/c\/d", "/a-b/c/d"),
    ("/", "/"),
    ("^$", "/"),
]
NOT_A_TEMPLATE = [
    "^raw/(?:v1|v2)/([0-9]+)/$",
    r"/files/\w+$",
    "/a|b/",
    "/items/[0-9]+",
    "^/items/(x)?$",
    "/files/(?P<name>[^/]+).json$",
    "/foo/?",
    "/a{b",
    "/a(b",
]


@pytest.mark.parametrize(("raw", "expected"), NORMALIZED)
def test_the_normalised_route_template(raw: str, expected: str) -> None:
    assert normalized_route_template(raw) == expected


@pytest.mark.parametrize("raw", NOT_A_TEMPLATE)
def test_regex_syntax_left_over_is_not_a_template(raw: str) -> None:
    assert normalized_route_template(raw) is None


def test_capture_groups_track_depth_escapes_and_classes() -> None:
    template = r"^(?P<a>[a-z]+(?:-[a-z]+)*)/(?P<b>x\))/([)]+)/(?:z)$"
    found = [(g.name, g.ordinal, g.top_level) for g in capture_groups(template)]

    assert found == [("a", 0, True), ("b", 1, True), (None, 2, True)]
    assert (
        template[capture_groups(template)[1].start : capture_groups(template)[1].end]
        == r"(?P<b>x\))"
    )


def test_a_nested_capture_counts_in_the_index_but_is_not_top_level() -> None:
    found = capture_groups("/(a(b))/(c)")

    assert [(g.ordinal, g.top_level) for g in found] == [
        (0, True),
        (1, False),
        (2, True),
    ]
    assert normalized_route_template("/(a(b))/(c)") == "/{0}/{2}"


def test_an_unbalanced_template_reports_no_group() -> None:
    assert capture_groups("/(a") == ()
    assert [group.name for group in capture_groups("/a)/(b)")] == [None]


@pytest.mark.parametrize(
    ("template", "declared", "expected"),
    [
        ("^(?P<a>[a-z]+(?:-[a-z]+)*)/(?P<b>x)$", ["b"], ["b"]),
        ("^(?P<a>[a-z]+)/(?P<b>x)$", ["b"], ["b"]),
        ("/items/(?P<slug>[a-z]+(?:-[a-z]+)*)$", ["slug"], []),
        (r"/files/(?P<name>[^/]+)\.(?P<ext>json|xml)$", ["ext"], []),
        (r"^(?P<name>[^/]+)\.(?P<ext>json|xml)$", ["name"], ["name"]),
        ("^(?P<a>x(?:y)*)(?P<b>z)$", ["a", "b"], ["a", "b"]),
        ("/{a}/{b}", ["a", "b"], ["a", "b"]),
        ("/api/{a}", ["a"], []),
    ],
)
def test_a_declared_param_with_no_literal_segment_before_it(
    template: str, declared: list[str], expected: list[str]
) -> None:
    assert path_params_without_a_literal_segment_before(template, declared) == expected


def test_event_fields_carry_the_normalised_template_only_when_there_is_one() -> None:
    request = MockGuardRequest(path="/items/5")
    assert route_template_event_fields(request.state) == {}

    request.state.guard_route_template = "/items/(?P<id>[0-9]+)/?"
    assert route_template_event_fields(request.state) == {
        "route_template": "/items/{id}"
    }

    request.state.guard_route_template = "^raw/(?:a|b)/$"
    assert route_template_event_fields(request.state) == {}

    request.state.guard_route_template = "/items/{id}"
    request.state.guard_route_unresolved = True
    assert route_template_event_fields(request.state) == {}


def _middleware(lookup: object) -> MagicMock:
    middleware = MagicMock()
    middleware.config = SecurityConfig(enable_redis=False)
    middleware.logger = MagicMock()
    middleware.agent_handler = None
    middleware.route_resolver.get_route_config = MagicMock(return_value=None)
    middleware.route_template = lookup
    return middleware


async def _run(middleware: MagicMock, request: MockGuardRequest) -> None:
    with patch(f"{_ROUTE_CONFIG}.extract_client_ip", AsyncMock(return_value="1.2.3.4")):
        assert await RouteConfigCheck(middleware).check(request) is None


async def test_the_first_check_records_the_raw_template_for_every_request() -> None:
    lookup = MagicMock(return_value="/items/(?P<id>[0-9]+)$")
    request = MockGuardRequest(path="/items/5")

    await _run(_middleware(lookup), request)

    lookup.assert_called_once_with("/items/5")
    assert request.state.guard_route_template == "/items/(?P<id>[0-9]+)$"


async def test_a_template_an_adapter_stamped_is_not_looked_up_again() -> None:
    lookup = MagicMock(return_value="/other")
    request = MockGuardRequest(path="/items/5")
    request.state.guard_route_template = "/items/{id}"

    await _run(_middleware(lookup), request)

    lookup.assert_not_called()
    assert request.state.guard_route_template == "/items/{id}"


async def test_an_unresolved_route_is_not_looked_up() -> None:
    lookup = MagicMock(return_value="/items/{id}")
    request = MockGuardRequest(path="/nope")
    request.state.guard_route_unresolved = True
    middleware = _middleware(lookup)

    with patch(f"{_ROUTE_CONFIG}.extract_client_ip", AsyncMock(return_value="1.2.3.4")):
        await RouteConfigCheck(middleware).check(request)

    lookup.assert_not_called()
    assert getattr(request.state, "guard_route_template", None) is None


async def test_a_failing_lookup_is_logged_and_the_request_goes_on() -> None:
    lookup = MagicMock(side_effect=RuntimeError("boom"))
    request = MockGuardRequest(path="/items/5")
    middleware = _middleware(lookup)

    await _run(middleware, request)

    assert getattr(request.state, "guard_route_template", None) is None
    middleware.logger.error.assert_called_once()


async def test_a_middleware_without_a_lookup_leaves_the_state_alone() -> None:
    middleware = _middleware(None)
    request = MockGuardRequest(path="/items/5")

    await _run(middleware, request)

    assert getattr(request.state, "guard_route_template", None) is None


def _agent() -> MagicMock:
    agent = MagicMock()
    agent.send_event = AsyncMock()
    return agent


async def test_the_middleware_event_carries_the_route_template() -> None:
    agent = _agent()
    config = SecurityConfig(enable_redis=False, agent_enable_events=True)
    bus = SecurityEventBus(agent, config)
    request = MockGuardRequest(path="/orgs/7/old/2024/")
    request.state.guard_route_template = "orgs/<int:org>/old/(?P<year>[0-9]{4})/$"

    await bus.send_middleware_event("ip_banned", request, "blocked", "why")

    event = agent.send_event.call_args.args[0]
    assert event.route_template == "/orgs/{org}/old/{year}/"
    assert event.endpoint == "/orgs/7/old/2024/"


async def test_the_middleware_event_has_no_template_for_an_unrouted_path() -> None:
    agent = _agent()
    config = SecurityConfig(enable_redis=False, agent_enable_events=True)
    bus = SecurityEventBus(agent, config)

    await bus.send_middleware_event(
        "ip_banned", MockGuardRequest(path="/nope"), "blocked", "why"
    )

    event = agent.send_event.call_args.args[0]
    assert event.model_dump().get("route_template") is None


async def test_send_agent_event_carries_the_route_template() -> None:
    agent = _agent()
    request = MockGuardRequest(path="/items/5")
    request.state.guard_route_template = "/items/{item_id:int}"

    await send_agent_event(agent, "x", "1.2.3.4", "a", "r", request)

    assert agent.send_event.call_args.args[0].route_template == "/items/{item_id}"


async def test_send_agent_event_without_a_request_has_no_template() -> None:
    agent = _agent()

    await send_agent_event(agent, "x", "1.2.3.4", "a", "r")

    assert agent.send_event.call_args.args[0].model_dump().get("route_template") is None


def test_the_metric_endpoint_tag_is_the_normalised_template() -> None:
    collector = MetricsCollector(
        MagicMock(), SecurityConfig(enable_redis=False, agent_enable_metrics=True)
    )
    request = MockGuardRequest(path="/items/5")
    request.state.guard_route_template = "/items/(?P<id>[0-9]+)/?"

    assert collector._metric_endpoint(request) == "/items/{id}"


def test_the_metric_endpoint_tag_keeps_the_raw_template_when_regex_is_left() -> None:
    collector = MetricsCollector(
        MagicMock(), SecurityConfig(enable_redis=False, agent_enable_metrics=True)
    )
    request = MockGuardRequest(path="/raw/v1/5/")
    request.state.guard_route_template = "^raw/(?:v1|v2)/([0-9]+)/$"

    assert collector._metric_endpoint(request) == "^raw/(?:v1|v2)/([0-9]+)/$"
