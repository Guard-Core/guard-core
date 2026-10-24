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
import ctypes
import gc
import importlib
import json
import logging
import os
import sys
import threading
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
# PERF_GATE_RAW=1 turns every determinism measure off (parity runs only).
RAW = os.environ.get("PERF_GATE_RAW") == "1"

# The scan yields to the event loop when a wall-clock slice (2 ms) has passed, so
# the number of yields, and the calls and instructions they cost, change from run
# to run. The gate turns the yield off in both arms; a missing name fails loudly.
for _module in (
    ()
    if RAW
    else ("guard_core._utils.detection_scan", "guard_core.handlers._suspatterns_regex")
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
if not RAW:
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


def start_every_regex_worker() -> None:
    """Create all worker threads of the shared regex pool before anything is counted.

    A ThreadPoolExecutor starts a new worker whenever the previous one has not yet
    gone idle at submit time, which is a race, and every start costs calls.
    """
    executor: Any = load("guard_core.detection_engine.compiler").shared_regex_executor()
    workers = executor._max_workers
    barrier = threading.Barrier(workers)
    for future in [executor.submit(barrier.wait) for _ in range(workers)]:
        future.result()


async def setup() -> tuple[Step, Any, Verify]:
    if ROW == "ban_check":
        return await ban_check_step()
    parts = ROW.split("-")
    if parts[0] == "allowed":
        return await allowed_step(parts[1])
    return await blocked_step(parts[1], "pen0" not in parts)


def loop_iteration_codes() -> tuple[Any, set[Any]]:
    """Code objects of one event-loop iteration (poll, process events, clock).

    How many iterations a Redis reply takes depends on when the server answers, so
    the counter skips these frames and the C calls `_run_once` itself makes. The
    callbacks it runs are still counted.
    """
    loop: Any = asyncio.get_running_loop()
    run_once = type(loop)._run_once.__code__
    skipped = {
        type(loop).time.__code__,
        type(loop._selector).select.__code__,
        type(loop)._process_events.__code__,
    }
    for name in ("_write_to_self", "_read_from_self", "_process_self_data"):
        method = getattr(type(loop), name, None)
        if method is not None:
            skipped.add(method.__code__)
    # A regex worker thread that finishes before the loop adds its done-callback
    # makes the loop thread run the state copy itself; after, the worker does.
    skipped.add(type(loop).call_soon_threadsafe.__code__)
    futures: Any = asyncio.futures
    skipped.update(
        const
        for const in futures._chain_future.__code__.co_consts
        if getattr(const, "co_name", "") == "_call_set_state"
    )
    return run_once, skipped


async def calls(one: Step, verify: Verify) -> dict[str, Any]:
    # Finalizers (__del__) run when the cyclic collector happens to fire, so it is
    # off inside the counted window; the instructions mode keeps it on.
    if not RAW:
        gc.collect()
        gc.disable()
    run_once, skipped = (None, set()) if RAW else loop_iteration_codes()
    counter = load("callcount").CallCounter(
        skipped, run_once, os.path.dirname(guard_core.__file__)
    )
    before = redis_commands() if ROW == "ban_check" else {}
    sys.setprofile(counter)
    for _ in range(N):
        last = await one()
    sys.setprofile(None)
    verify(last)
    extra: dict[str, Any] = {}
    if ROW == "ban_check":
        after = redis_commands()
        delta = {
            k: round((after[k] - before.get(k, 0)) / N, 2)
            for k in after
            if k != "info" and after[k] != before.get(k, 0)
        }
        extra["redis_commands_per_request"] = dict(sorted(delta.items()))
    return {
        "calls_per_request": round(counter.total / N, 2),
        "python_calls_per_request": round(counter.python / N, 2),
        "guard_core_calls_per_request": round(counter.mine / N, 2),
        **extra,
    }


async def workers(one: Step, verify: Verify) -> dict[str, Any]:
    """Calls made on every thread but the main one (3.12+ only), per request."""
    main = threading.get_ident()
    count = 0

    def prof_fn(frame: Any, event: str, arg: Any) -> None:
        nonlocal count
        if event in ("call", "c_call") and threading.get_ident() != main:
            count += 1

    set_all = vars(threading)["setprofile_all_threads"]
    set_all(prof_fn)
    for _ in range(N):
        last = await one()
    set_all(None)
    verify(last)
    return {"worker_calls_per_request": round(count / N, 2)}


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
    if not RAW:
        install_step_clock()
        start_every_regex_worker()
    if MODE == "calls":
        result = await calls(one, verify)
    elif MODE == "cpu":
        result = await cpu(one, verify)
    elif MODE == "workers":
        result = await workers(one, verify)
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


def window_main() -> None:
    """One process: set up and warm up, then run the N requests inside one C call.

    callgrind collects only inside PyRun_SimpleString (`--toggle-collect`), so the
    start-up cost is not in the count and one process gives the per-request cost.
    """
    loop = asyncio.new_event_loop()
    one, closer, verify = loop.run_until_complete(setup())
    install_step_clock()
    start_every_regex_worker()

    async def measured() -> None:
        for _ in range(N):
            last = await one()
        verify(last)

    vars(sys.modules["__main__"])["WINDOW"] = lambda: loop.run_until_complete(
        measured()
    )
    api: Any = ctypes.pythonapi
    api.PyRun_SimpleString.argtypes = [ctypes.c_char_p]
    status = api.PyRun_SimpleString(b"import __main__; __main__.WINDOW()")
    assert status == 0, "the measured window raised"
    if ROW == "ban_check":
        loop.run_until_complete(closer.delete_pattern("*"))
        loop.run_until_complete(closer.close())
    else:
        loop.run_until_complete(closer.aclose())


if MODE == "window":
    window_main()
else:
    asyncio.run(main())
