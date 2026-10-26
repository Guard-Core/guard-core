import json

from tests.live_smoke.driver import ScenarioContext, run_in_app_container, wait_until
from tests.live_smoke.registry import scenario

_BASE = {
    "auto_ban_threshold": 1000,
    "rate_limit": 1000,
    "excluded_detection_headers": ["x-real-ip", "x-forwarded-for"],
}

_BODY_CAP = 2048
_SMALL_NOTE = "small"
_LARGE_NOTE = "x" * (_BODY_CAP + 1024)


@scenario(
    covers={"custom_response_modifier_max_body_bytes"},
    config={
        **_BASE,
        "custom_response_modifier_max_body_bytes": _BODY_CAP,
        "smoke_body_reading_modifier": True,
    },
)
def custom_response_modifier_max_body_bytes_gates_the_body_the_modifier_reads(
    ctx: ScenarioContext,
) -> None:
    mark = ctx.stack.logs.mark()

    small = ctx.client.post("/basic/echo", json={"note": _SMALL_NOTE})
    assert small.status_code == 200, small.status_code
    assert int(small.headers["Content-Length"]) <= _BODY_CAP, (
        "the small echo response must stay under the cap for this scenario to "
        f"mean anything: {small.headers['Content-Length']}"
    )
    assert small.headers.get("X-Smoke-Body-Bytes") == small.headers["Content-Length"], (
        "a response whose declared Content-Length is under the cap must expose "
        f".body to the modifier: {small.headers.get('X-Smoke-Body-Bytes')!r}"
    )

    large = ctx.client.post("/basic/echo", json={"note": _LARGE_NOTE})
    assert large.status_code == 200, large.status_code
    declared = large.headers["Content-Length"]
    assert int(declared) > _BODY_CAP, f"the large echo response is {declared} bytes"
    assert large.headers.get("X-Smoke-Body-Bytes") == "unavailable", (
        "a response whose declared Content-Length is over the cap must raise "
        f"on .body: {large.headers.get('X-Smoke-Body-Bytes')!r}"
    )

    refusal = (
        f"the declared Content-Length {declared} is over {_BODY_CAP} bytes; "
        "header edits still apply"
    )
    assert wait_until(
        lambda: any(refusal in line for line in ctx.stack.logs.lines_since(mark)),
        timeout=15.0,
    ), (
        "the over-cap refusal was never logged; "
        f"recent lines: {ctx.stack.logs.lines_since(mark)[-10:]}"
    )


_BARE_UNION_SELECT = "UNION SELECT"
_SQLI = "' UNION SELECT password FROM admin--"


@scenario(
    covers={"flag_bare_union_select"},
    config={
        **_BASE,
        "flag_bare_union_select": False,
        "detection_semantic_threshold": 1.0,
    },
)
def flag_bare_union_select_false_admits_only_the_bare_keywords(
    ctx: ScenarioContext,
) -> None:
    bare = ctx.client.post("/basic/echo", json={"note": _BARE_UNION_SELECT})
    assert bare.status_code == 200, (
        "flag_bare_union_select=False must stop flagging a value that is only "
        f"UNION SELECT: {bare.status_code}"
    )

    full = ctx.client.post("/basic/echo", json={"note": _SQLI})
    assert full.status_code == 400, (
        "flag_bare_union_select=False turns off only the bare row; a UNION SELECT "
        f"with a select list must still be blocked: {full.status_code}"
    )


_DOWNLOAD_URL = "https://geo-mirror.smoke.invalid/data/country_asn.mmdb"
_DEFAULT_DOWNLOAD_URL = "https://ipinfo.io/data/free/country_asn.mmdb"

_DOWNLOAD_URL_PROBE = """
import asyncio
import json
from pathlib import Path

import aiohttp

from guard_core.models import SecurityConfig

fetched = []


async def record_instead_of_fetching(self, url, **kwargs):
    fetched.append(str(url))
    raise aiohttp.ClientConnectionError("smoke probe: no network call is made")


aiohttp.ClientSession.get = record_instead_of_fetching

config = SecurityConfig(
    blocked_countries=["ZZ"],
    ipinfo_token="smoke-url-token",
    ipinfo_db_path=Path("/tmp/smoke_ipinfo_url_probe.mmdb"),
    ipinfo_download_url={url!r},
)
asyncio.run(config.geo_ip_handler.initialize())
print("SMOKE_FETCHED " + json.dumps(fetched))
"""


def _fetched_urls(output: str) -> list[str]:
    for line in output.splitlines():
        if line.startswith("SMOKE_FETCHED "):
            urls: list[str] = json.loads(line.removeprefix("SMOKE_FETCHED "))
            return urls
    raise AssertionError(f"the probe never reported the URLs it saw: {output!r}")


@scenario(
    covers={"ipinfo_download_url"},
    config={**_BASE, "ipinfo_download_url": _DOWNLOAD_URL},
)
def ipinfo_download_url_is_the_url_the_database_download_requests(
    ctx: ScenarioContext,
) -> None:
    result = run_in_app_container(
        _DOWNLOAD_URL_PROBE.format(url=_DOWNLOAD_URL), timeout=40.0
    )
    assert result.returncode == 0, result.stdout + result.stderr

    fetched = _fetched_urls(result.stdout)
    assert fetched, "the database download never asked for any URL"
    assert set(fetched) == {_DOWNLOAD_URL}, (
        "the download must request exactly the configured ipinfo_download_url, "
        f"never the default {_DEFAULT_DOWNLOAD_URL}: {fetched}"
    )
