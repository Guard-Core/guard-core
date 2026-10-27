from concurrent.futures import ThreadPoolExecutor

import httpx

from tests.live_smoke.driver import BASE_URL, ScenarioContext
from tests.live_smoke.registry import scenario

_BASE = {
    "auto_ban_threshold": 1000,
    "excluded_detection_headers": ["x-real-ip", "x-forwarded-for"],
}
_LIMIT = 60
_BURST = 12


def _worker_pid(headers: dict[str, str] | None = None) -> int | None:
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as fresh:
        response = fresh.get("/surfaces/worker", headers=headers)
    return response.json()["pid"] if response.status_code == 200 else None


def _concurrent_pids(
    count: int, headers: dict[str, str] | None = None
) -> list[int | None]:
    # One idle worker wins every connection of a sequential client, so the
    # requests overlap: a busy worker leaves the next connection to the other.
    with ThreadPoolExecutor(max_workers=_BURST) as pool:
        return list(pool.map(lambda _: _worker_pid(headers), range(count)))


@scenario(
    covers={"surface:two_workers_share_the_rate_limit"},
    config={**_BASE, "rate_limit": _LIMIT, "rate_limit_window": 60},
)
def a_rate_limit_is_counted_across_both_gunicorn_workers(
    ctx: ScenarioContext,
) -> None:
    pids = _concurrent_pids(_LIMIT)
    assert None not in pids, f"a request inside the limit was refused: {pids}"
    assert len(set(pids)) == 2, (
        f"the {_LIMIT} requests were not served by both workers: {set(pids)}"
    )
    counts = sorted(pids.count(pid) for pid in set(pids))
    assert counts[0] < _LIMIT, counts
    over = _worker_pid()
    assert over is None, (
        f"request {_LIMIT + 1} was admitted although the workers served "
        f"{counts} of the {_LIMIT} requests: neither alone reached the limit, so "
        "the count is not shared through Redis"
    )


@scenario(
    covers={"surface:two_workers_share_the_ban"},
    config={**_BASE, "rate_limit": 1000, "auto_ban_threshold": 3},
)
def a_ban_earned_on_one_worker_holds_on_both(ctx: ScenarioContext) -> None:
    victim = {"X-Smoke-Client": "192.168.60.3"}
    before = set(_concurrent_pids(24, victim))
    assert None not in before and len(before) == 2, (
        f"the client was not served by both workers before the ban: {before}"
    )

    for _ in range(4):
        ctx.client.get("/basic/ip", headers={**victim, "User-Agent": "badbot"})

    after = _concurrent_pids(24, victim)
    assert all(pid is None for pid in after), (
        "a client banned by hostile requests was still served by a worker: "
        f"{sorted({pid for pid in after if pid is not None})}"
    )
