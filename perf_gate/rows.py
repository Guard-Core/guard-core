"""One per-request workload of the perf gate, run in its own process.

The engine is on PYTHONPATH.

usage: python rows.py <row> <calls|run|cpu> <n> <redis url or empty> [rounds]
Modes: calls (deterministic Python calls per request), run (warm-up then n
requests, no profiler, for valgrind), cpu (process CPU microseconds per
request, median of rounds).
Prints one JSON line. Rows: ban_check, allowed-<get|post>-redis-<off|on>,
blocked-<blacklist|banned>-pen<1|0>-redis<off|on>, blocked-pattern-redis<off|on>.
"""

import asyncio
import cProfile
import importlib
import json
import logging
import os
import pstats
import sys
import time
import uuid
import warnings
from collections.abc import Awaitable, Callable
from functools import partial
from typing import Any

warnings.simplefilter("ignore")
logging.disable(logging.CRITICAL)

ROW, MODE, N, URL = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
ROUNDS = int(sys.argv[5]) if len(sys.argv) > 5 else 5
BODY = json.dumps({"name": "Mary", "city": "Rome", "note": "hello world"}).encode()
PATTERN_PATH = "/api/items/7?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"


def load(name: str) -> Any:
    return importlib.import_module(name)


guard_core = load("guard_core")

# The scan yields to the event loop when a wall-clock slice (2 ms) has passed, so
# the number of yields, and the calls and instructions they cost, change from run
# to run. The gate turns the yield off in both arms; a missing name fails loudly.
for _module in (
    "guard_core._utils.detection_scan",
    "guard_core.handlers._suspatterns_regex",
):
    assert hasattr(load(_module), "_EVENT_LOOP_SLICE_SECONDS"), _module
    load(_module)._EVENT_LOOP_SLICE_SECONDS = float("inf")


class StepClock:
    """The clocks the engine reads, advancing 1 us per read (the real ones vary).

    The pattern monitor compares each pattern's run time with the running average
    and does extra statistics only above it, which is a coin flip on a real clock.
    """

    def __init__(self) -> None:
        self.ticks = 0
        self.epoch = time.time()

    def monotonic(self) -> float:
        self.ticks += 1
        return 1000.0 + self.ticks * 1e-6

    def time(self) -> float:
        return self.epoch + self.monotonic()

    perf_counter = thread_time = process_time = monotonic

    def __getattr__(self, name: str) -> Any:
        return getattr(time, name)


def install_step_clock() -> None:
    """Swap the `time` module global of every guard module for one StepClock."""
    clock = StepClock()
    for name, module in list(sys.modules.items()):
        if name.startswith("guard") and getattr(module, "time", None) is time:
            vars(module)["time"] = clock


load("guard")
install_step_clock()
Step = Callable[[], Awaitable[Any]]
Verify = Callable[[Any], None]


def build_app(echo: bool, fields: dict[str, Any]) -> Any:
    fastapi, guard = load("fastapi"), load("guard")
    app = fastapi.FastAPI()

    async def item(item_id: int) -> dict[str, int]:
        return {"id": item_id}

    app.get("/api/items/{item_id}")(item)
    if echo:

        async def echo_body(request: Any) -> dict[str, int]:
            return {"n": len(await request.body())}

        echo_body.__annotations__["request"] = fastapi.Request
        app.post("/api/echo")(echo_body)
    base: dict[str, Any] = {
        "enable_redis": False,
        "rate_limit": 10_000_000,
        "rate_limit_window": 60,
        "auto_ban_threshold": 10**6,
    }
    if URL:
        base.update(
            enable_redis=True,
            redis_url=URL,
            redis_prefix=f"perfgate{os.getpid()}:",
        )
    app.add_middleware(
        guard.SecurityMiddleware, config=guard.SecurityConfig(**base, **fields)
    )
    return app


def client_for(app: Any, ip: str) -> Any:
    httpx = load("httpx")
    transport = httpx.ASGITransport(app=app, client=(ip, 51000))
    return httpx.AsyncClient(transport=transport, base_url="http://api.example.com")


async def open_client(app: Any, ip: str) -> Any:
    c = client_for(app, ip)
    await c.__aenter__()
    return c


async def allowed_step(kind: str) -> tuple[Step, Any, Verify]:
    app = build_app(True, {})
    c = await open_client(app, "203.0.113.77")

    async def one() -> None:
        if kind == "get":
            r = await c.get("/api/items/7")
        else:
            r = await c.post(
                "/api/echo",
                content=BODY,
                headers={"content-type": "application/json"},
            )
        assert r.status_code == 200, r.status_code

    for _ in range(50):
        await one()
    return one, c, lambda last: None


async def blocked_step(scenario: str, pen: bool) -> tuple[Step, Any, Verify]:
    pattern = scenario == "pattern"
    ip = "203.0.113.10" if pattern else "198.51.100.21"
    path = PATTERN_PATH if pattern else "/api/items/7"
    status = 400 if pattern else 403
    fields: dict[str, Any] = {"enable_penetration_detection": pen}
    if scenario == "blacklist":
        fields["blacklist"] = [ip]
    app = build_app(False, fields)
    async with client_for(app, "203.0.113.77") as warm:
        for _ in range(10):
            assert (await warm.get("/api/items/7")).status_code == 200
    if scenario == "banned":
        ban = load("guard_core.handlers.ipban_handler").ip_ban_manager
        assert await ban.ban_ip(ip, 3600) is not False
    c = await open_client(app, ip)

    def verify(response: Any) -> None:
        assert response.status_code == status, response.status_code

    for _ in range(40):
        verify(await c.get(path))
    return partial(c.get, path), c, verify


async def ban_check_step() -> tuple[Step, Any, Verify]:
    ban = load("guard_core.handlers.ipban_handler").ip_ban_manager
    handler_cls = load("guard_core.handlers.redis_handler").RedisManager
    cfg = load("guard_core.models").SecurityConfig(
        redis_url=URL,
        redis_prefix=f"perfgate:{uuid.uuid4().hex}:",
        enable_redis=True,
        rate_limit=10,
        ban_on_hostile_signals=False,
    )
    handler = handler_cls(cfg)
    await handler.initialize()
    ban.config = cfg
    ban.redis_handler = handler

    one = partial(ban.is_ip_banned, "198.51.100.9")
    for _ in range(20):
        await one()
    return one, handler, lambda last: None


def redis_commands() -> dict[str, int]:
    info = load("redis").Redis.from_url(URL).info("commandstats")
    return {k[len("cmdstat_") :]: v["calls"] for k, v in info.items()}


async def setup() -> tuple[Step, Any, Verify]:
    if ROW == "ban_check":
        return await ban_check_step()
    parts = ROW.split("-")
    if parts[0] == "allowed":
        return await allowed_step(parts[1])
    return await blocked_step(parts[1], "pen0" not in parts)


async def calls(one: Step, verify: Verify) -> dict[str, Any]:
    extra: dict[str, Any] = {}
    if ROW.startswith("blocked"):
        prof = cProfile.Profile()
        prof.enable()
        for _ in range(N):
            last = await one()
        prof.disable()
        verify(last)
        stats = pstats.Stats(prof).__dict__["stats"]
        root = os.path.dirname(guard_core.__file__)
        mine = sum(
            nc for (f, _, _), (_, nc, _, _, _) in stats.items() if f.startswith(root)
        )
        extra["guard_core_calls_per_request"] = round(mine / N, 2)
        total = sum(nc for (_, nc, _, _, _) in stats.values())
        return {"calls_per_request": round(total / N, 2), **extra}
    count = 0

    def prof_fn(frame: Any, event: str, arg: Any) -> None:
        nonlocal count
        if event == "call":
            count += 1

    before = redis_commands() if ROW == "ban_check" else {}
    sys.setprofile(prof_fn)
    for _ in range(N):
        last = await one()
    sys.setprofile(None)
    verify(last)
    if ROW == "ban_check":
        after = redis_commands()
        delta = {
            k: round((after[k] - before.get(k, 0)) / N, 2)
            for k in after
            if k != "info" and after[k] != before.get(k, 0)
        }
        extra["redis_commands_per_request"] = dict(sorted(delta.items()))
    return {"calls_per_request": round(count / N, 2), **extra}


async def cpu(one: Step, verify: Verify) -> dict[str, Any]:
    samples = []
    for _ in range(ROUNDS):
        t0 = time.process_time()
        for _ in range(N):
            last = await one()
        verify(last)
        samples.append(1e6 * (time.process_time() - t0) / N)
    return {"cpu_us_per_request": round(sorted(samples)[len(samples) // 2], 1)}


async def main() -> None:
    one, closer, verify = await setup()
    install_step_clock()
    if MODE == "calls":
        result = await calls(one, verify)
    elif MODE == "cpu":
        result = await cpu(one, verify)
    else:
        for _ in range(N):
            last = await one()
        verify(last)
        result = {}
    if ROW == "ban_check":
        await closer.delete_pattern("*")
        await closer.close()
    else:
        await closer.aclose()
    print(json.dumps({"engine": os.path.dirname(guard_core.__file__), **result}))


asyncio.run(main())
