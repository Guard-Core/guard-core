from tests.live_smoke.driver import ScenarioContext
from tests.live_smoke.registry import scenario

_BLOCKS_BASE = {
    "auto_ban_threshold": 1000,
    "rate_limit": 1000,
    "excluded_detection_headers": ["x-real-ip", "x-forwarded-for"],
    "enable_redis": False,
}


@scenario(
    covers={"surface:building_block_ip_access", "surface:cidr_rules"},
    config=_BLOCKS_BASE,
)
def check_ip_access_and_is_ip_allowed_apply_the_cidr_blacklist(
    ctx: ScenarioContext,
) -> None:
    blocked = ctx.client.get("/blocks/ip-access", params={"dashed_ip": "192-168-100-7"})
    assert blocked.status_code == 200, blocked.text
    assert blocked.json()["allowed"] is False, blocked.text
    assert blocked.json()["is_ip_allowed"] is False, blocked.text

    allowed = ctx.client.get("/blocks/ip-access", params={"dashed_ip": "203-0-113-5"})
    assert allowed.json()["allowed"] is True, allowed.text
    assert allowed.json()["is_ip_allowed"] is True, allowed.text

    inside = ctx.client.get(
        "/access/ip-blacklist", headers={"X-Smoke-Client": "192.168.1.5"}
    )
    outside = ctx.client.get("/access/ip-blacklist")
    assert (inside.status_code, outside.status_code) == (403, 200), (
        "the require_ip blacklist route did not refuse an address inside its "
        f"CIDR and admit one outside it: {inside.status_code}, {outside.status_code}"
    )


@scenario(
    covers={"surface:admin_routes", "surface:manual_unban"},
    config={
        **_BLOCKS_BASE,
        "auto_ban_threshold": 2,
    },
)
def admin_routes_serve_localhost_only_and_unban_lifts_a_ban(
    ctx: ScenarioContext,
) -> None:
    admin_calls = (
        ("GET", "/admin/stats", None),
        ("GET", "/admin/cloud-status", None),
        ("POST", "/admin/clear-cache", None),
        ("PUT", "/admin/emergency-mode", False),
    )
    for method, path, body in admin_calls:
        refused = ctx.client.request(method, path, json=body)
        assert refused.status_code == 403, (
            f"{method} {path} answered a non-localhost client: {refused.status_code}"
        )
        served = ctx.client.request(
            method, path, json=body, headers={"X-Smoke-Client": "127.0.0.1"}
        )
        assert served.status_code == 200, (
            f"{method} {path} refused the localhost client: "
            f"{served.status_code} {served.text[:120]}"
        )

    victim = {"X-Smoke-Client": "203.0.113.60"}
    for _ in range(3):
        ctx.client.get("/basic/ip", headers={**victim, "User-Agent": "badbot"})
    banned = ctx.client.get("/basic/ip", headers=victim)
    assert banned.status_code == 403, (
        f"the client did not end banned after hostile requests: {banned.status_code}"
    )

    unban = ctx.client.post(
        "/admin/unban-ip",
        json="203.0.113.60",
        headers={"X-Smoke-Client": "127.0.0.1"},
    )
    assert unban.status_code == 200, unban.text
    lifted = ctx.client.get("/basic/ip", headers=victim)
    assert lifted.status_code == 200, (
        f"the manual unban did not lift the ban: {lifted.status_code}"
    )


@scenario(
    covers={
        "surface:building_block_behavior",
        "surface:building_block_rate_limit_manager",
        "surface:building_block_security_headers_manager",
        "surface:building_block_bounded_readers",
        "surface:building_block_endpoint_key_problems",
    },
    config=_BLOCKS_BASE,
)
def public_building_blocks_do_their_documented_work(ctx: ScenarioContext) -> None:
    behavior = ctx.client.get("/blocks/behavior").json()
    assert behavior["rule_id_is_stable"] is True, behavior
    assert behavior["threshold_crossed_on"] == [False, False, True], behavior
    assert behavior["request_is_bounded_body_reader"] is True, behavior
    assert behavior["response_is_bounded_response_reader"] is True, behavior

    verdicts = [
        ctx.client.get("/blocks/rate-limit").json()["blocked"] for _ in range(3)
    ]
    assert verdicts == [False, False, True], (
        f"RateLimitManager.check_rate_limit at 2 per window: {verdicts}"
    )

    headers = ctx.client.get("/blocks/security-headers").json()
    assert headers["singleton"] is True, headers
    assert headers["headers"]["Strict-Transport-Security"].startswith(
        "max-age=31536000"
    ), headers
    assert headers["headers"]["X-Frame-Options"] == "SAMEORIGIN", headers

    clean = ctx.client.get("/blocks/endpoint-key-problems", params={"key": "/api/ok"})
    dotted = ctx.client.get(
        "/blocks/endpoint-key-problems", params={"key": "/api/DOTDOT/x"}
    )
    assert clean.json()["problems"] == [], clean.text
    assert len(dotted.json()["problems"]) == 1, dotted.text


@scenario(covers={"surface:custom_pattern_api"}, config=_BLOCKS_BASE)
def custom_patterns_can_be_added_and_removed_at_runtime(ctx: ScenarioContext) -> None:
    probe = {"q": "zzcustomzz"}
    assert ctx.client.get("/basic/ip", params=probe).status_code == 200

    added = ctx.client.post(
        "/blocks/patterns", json={"action": "add", "pattern_reversed": "zzmotsuczz"}
    )
    assert added.json() == {"changed": True}, added.text
    assert ctx.client.get("/basic/ip", params=probe).status_code == 400, (
        "a custom pattern added through the API did not flag a matching request"
    )

    removed = ctx.client.post(
        "/blocks/patterns", json={"action": "remove", "pattern_reversed": "zzmotsuczz"}
    )
    assert removed.json() == {"changed": True}, removed.text
    assert ctx.client.get("/basic/ip", params=probe).status_code == 200, (
        "a removed custom pattern still flags the request"
    )
