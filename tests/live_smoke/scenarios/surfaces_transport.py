from tests.live_smoke.driver import ScenarioContext, wait_until, websocket_exchange
from tests.live_smoke.registry import scenario

_BASE = {
    "auto_ban_threshold": 1000,
    "rate_limit": 1000,
    "excluded_detection_headers": ["x-real-ip", "x-forwarded-for"],
}

_XSS_QUERY = "%3Cscript%3Ealert(1)%3C/script%3E"


@scenario(covers={"surface:websocket_guard"}, config=_BASE)
def websocket_guard_admits_a_clean_client_and_refuses_a_hostile_one(
    ctx: ScenarioContext,
) -> None:
    status, echoed = websocket_exchange("/ws", text="hello")
    assert (status, echoed) == (101, "hello"), (
        f"a clean websocket handshake was not accepted and echoed: {status}, {echoed}"
    )

    status, echoed = websocket_exchange("/ws", {"User-Agent": "badbot"})
    assert (status, echoed) == (403, None), (
        f"a blocked user agent opened a guarded websocket: {status}, {echoed}"
    )

    status, echoed = websocket_exchange(f"/ws?q={_XSS_QUERY}")
    assert (status, echoed) == (403, None), (
        f"an attack in the websocket query was admitted: {status}, {echoed}"
    )

    status, echoed = websocket_exchange("/ws", text="after")
    assert (status, echoed) == (101, "after"), (
        "the refusals of a hostile client closed the door on a clean one: "
        f"{status}, {echoed}"
    )


@scenario(
    covers={"surface:websocket_guard"},
    config={**_BASE, "rate_limit": 2, "rate_limit_window": 60},
)
def websocket_guard_rate_limits_the_handshake(ctx: ScenarioContext) -> None:
    first = websocket_exchange("/ws", text="one")
    second = websocket_exchange("/ws", text="two")
    third = websocket_exchange("/ws", text="three")
    assert first == (101, "one") and second == (101, "two"), (first, second)
    assert third == (403, None), (
        f"the third handshake inside a 2 per window limit was admitted: {third}"
    )


@scenario(covers={"surface:pure_asgi_middleware"}, config=_BASE)
def pure_asgi_middleware_guards_its_mounted_app(ctx: ScenarioContext) -> None:
    clean = ctx.client.get("/pure/ping")
    assert clean.status_code == 200 and clean.json() == {"pure": True}, clean.text
    assert clean.headers.get("x-content-type-options") == "nosniff", dict(clean.headers)

    refused = ctx.client.get("/pure/ping", headers={"User-Agent": "pure-only-bot"})
    assert refused.status_code == 403, (
        "the pure-ASGI middleware did not refuse the user agent only its config "
        f"blocks: {refused.status_code}"
    )

    elsewhere = ctx.client.get("/basic/ip", headers={"User-Agent": "pure-only-bot"})
    assert elsewhere.status_code == 200, (
        "the user agent blocked only by the pure-ASGI config was refused by the "
        f"classic middleware: {elsewhere.status_code}"
    )

    attack = ctx.client.get(f"/pure/ping?q={_XSS_QUERY}")
    assert attack.status_code == 400, (
        f"an attack through the pure-ASGI mount was admitted: {attack.status_code}"
    )


@scenario(covers={"surface:status_route"}, config=_BASE)
def status_route_reports_initialization(ctx: ScenarioContext) -> None:
    response = ctx.client.get("/_guard/status")
    assert response.status_code == 200, response.text
    body = response.json()
    assert {"cloud_providers", "geo_ip"} <= set(body), body
    providers = body["cloud_providers"]
    assert providers, body
    for name, state in providers.items():
        assert {"ready", "last_refreshed", "entries"} <= set(state), (name, state)


@scenario(
    covers={"surface:lifespan_edges", "surface:middleware_introspection"}, config=_BASE
)
def lifespan_runs_its_start_and_stop_edges_around_a_restart(
    ctx: ScenarioContext,
) -> None:
    ctx.stack.restart_service()
    assert wait_until(
        lambda: ctx.client.get("/health").status_code == 200, timeout=60
    ), "the app did not come back after a restart"

    full = ctx.stack.logs.full_text()
    boot = ctx.stack.logs.current_boot_text()
    assert "FastAPI Guard Advanced Example shutting down" in full, (
        "the lifespan shutdown edge of the previous boot never ran"
    )
    assert "FastAPI Guard Advanced Example starting up" in boot, (
        "the lifespan startup edge did not run on the new boot"
    )

    info = ctx.client.get("/surfaces/introspect")
    assert info.status_code == 200, info.text
    body = info.json()
    assert set(body["allowed_methods"]) == {
        "DELETE",
        "GET",
        "PATCH",
        "POST",
        "PUT",
    }, body["allowed_methods"]
    assert "/assets" in body["static_route_prefixes"], body["static_route_prefixes"]
    assert body["agent_stats_is_dict"] is True
    assert "cloud_providers" in body["initialization_status"], body


@scenario(covers={"surface:static_files_bypass"}, config=_BASE)
def static_files_bypass_clears_a_served_ts_or_map_file_only(
    ctx: ScenarioContext,
) -> None:
    for path in ("/assets/hello.txt", "/assets/module.ts", "/assets/bundle.js.map"):
        served = ctx.client.get(path)
        assert served.status_code == 200, (
            f"{path} exists in the static mount and must be served: "
            f"{served.status_code} {served.text[:80]}"
        )
    for path in ("/assets/missing.ts", "/assets/missing.js.map"):
        missing = ctx.client.get(path)
        assert missing.status_code == 400, (
            f"{path} is not in the static mount and must still match the probe "
            f"row: {missing.status_code}"
        )


@scenario(covers={"surface:http_methods"}, config=_BASE)
def every_routed_http_method_passes_and_an_unrouted_one_is_refused(
    ctx: ScenarioContext,
) -> None:
    for method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        response = ctx.client.request(method, "/methods/resource")
        assert response.status_code == 200, (method, response.status_code)
        assert response.json() == {"method": method}, response.text

    for method in ("HEAD", "OPTIONS", "TRACE"):
        response = ctx.client.request(method, "/methods/resource")
        assert response.status_code == 405, (
            f"{method} is not routed and must answer 405, not pass or crash: "
            f"{response.status_code}"
        )
    head = ctx.client.request("HEAD", "/methods/resource")
    allowed = {
        item.strip() for item in head.headers.get("allow", "").split(",") if item
    }
    assert allowed == {"GET", "POST", "PUT", "PATCH", "DELETE"}, allowed


@scenario(covers={"surface:streaming_response"}, config=_BASE)
def a_streamed_response_arrives_whole_with_the_security_headers(
    ctx: ScenarioContext,
) -> None:
    with ctx.client.stream("GET", "/stream/numbers") as response:
        body = "".join(response.iter_text())
        headers = dict(response.headers)
    assert response.status_code == 200
    assert body == "".join(f"line-{number}\n" for number in range(5)), body
    assert headers.get("x-content-type-options") == "nosniff", headers
    assert "strict-transport-security" in headers, headers

    attack = ctx.client.get(f"/stream/numbers?q={_XSS_QUERY}")
    assert attack.status_code == 400, (
        f"an attack on a streaming route was admitted: {attack.status_code}"
    )
