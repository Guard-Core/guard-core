"""What one multipart upload costs a Guard adapter with 64 uploads in flight.

usage: python -m perf_gate.multipart_cells cell <reader> <shape> <size> <n> [--tm]
    n: requests in flight, reader: fastapi, flask or django,
    shape: mp-flat, mp-escaped or mp-binary
Run it from a checkout of the adapter (fastapi-guard, flaskapi-guard or
djapi-guard) with PYTHONPATH set to that checkout and to a guard-core tree, in
the adapter's own environment (it imports the framework). One cell is one
reader, one multipart body shape and one size, posted by `inflight` requests at
once. `detection_max_file_inspect_bytes` (and, for a release that has no such
field, `detection_max_body_inspect_bytes`) is the body size, so the whole body is
scanned, and the body read slots are 64.

  without --tm: the peak RSS of the process, CPU seconds per MB and the wall
                time of the `inflight` requests
  with --tm   : tracemalloc on after the warm-up, the peak of traced memory over
                the requests (use inflight 1 for the peak per request)

It prints one JSON line. The framework imports sit inside the reader functions.
"""

import argparse
import asyncio
import json
import logging
import resource
import sys
import threading
import time
import tracemalloc
import types
import warnings
from collections.abc import Callable

from perf_gate.multipart_cell_inputs import (
    _REFUSAL_REASONS,
    _config_kwargs,
    _note_refusal,
    build_multipart,
)


def _rss_bytes() -> int:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak if sys.platform == "darwin" else peak * 1024


def _threaded(call: Callable[[], int], slots: int) -> tuple[list[int], float, float]:
    statuses: list[int] = [0] * slots
    start = threading.Barrier(slots + 1)

    def worker(index: int) -> None:
        start.wait()
        statuses[index] = call()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(slots)]
    for thread in threads:
        thread.start()
    cpu0, wall0 = time.process_time(), time.perf_counter()
    start.wait()
    for thread in threads:
        thread.join()
    return statuses, time.process_time() - cpu0, time.perf_counter() - wall0


class _Tm:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def start(self) -> None:
        if self.enabled:
            tracemalloc.start()
            tracemalloc.reset_peak()

    def peak_mb(self) -> float | None:
        if not self.enabled:
            return None
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        return round(peak / 1048576, 2)


def _report(
    reader: str,
    shape: str,
    size: int,
    inflight: int,
    statuses: list[int],
    cpu: float,
    wall: float,
    rss_before: int,
    body_len: int,
    tm: _Tm,
) -> dict[str, object]:
    counts: dict[int, int] = {}
    for status in statuses:
        counts[status] = counts.get(status, 0) + 1
    megabytes = inflight * body_len / 1048576
    peak = tm.peak_mb()
    return {
        "reader": reader,
        "shape": shape,
        "size": size,
        "body_len": body_len,
        "inflight": inflight,
        "statuses": counts,
        "refusal_reasons": dict(_REFUSAL_REASONS),
        "cpu_s": round(cpu, 3),
        "cpu_s_per_mb": round(cpu / megabytes, 4),
        "wall_s": round(wall, 3),
        "peak_rss_mb": round(_rss_bytes() / 1048576, 1),
        "peak_rss_growth_mb": round((_rss_bytes() - rss_before) / 1048576, 1),
        "tracemalloc_peak_mb": peak,
        "tracemalloc_peak_mb_per_request": (
            None if peak is None else round(peak / inflight, 3)
        ),
    }


def cell_fastapi(shape: str, size: int, inflight: int, tm: _Tm) -> dict[str, object]:
    import httpx
    from fastapi import FastAPI, Request
    from guard import SecurityConfig, SecurityMiddleware

    app = FastAPI()

    @app.post("/up")
    async def up(request: Request) -> dict[str, int]:
        return {"n": len(await request.body())}

    app.add_middleware(
        SecurityMiddleware,
        config=SecurityConfig(**_config_kwargs(size, SecurityConfig.model_fields)),
    )
    body, content_type = build_multipart(shape, size)
    headers = {"content-type": content_type, "X-Forwarded-For": "203.0.113.9"}

    async def main() -> dict[str, object]:
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 51000))
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test", timeout=600
        ) as client:
            await client.post("/up", content=b"warm", headers=headers)
            rss_before = _rss_bytes()
            tm.start()
            cpu0, wall0 = time.process_time(), time.perf_counter()
            responses = await asyncio.gather(
                *(
                    client.post("/up", content=body, headers=headers)
                    for _ in range(inflight)
                )
            )
            cpu, wall = time.process_time() - cpu0, time.perf_counter() - wall0
        statuses = [
            _note_refusal(response.status_code, response.text) for response in responses
        ]
        return _report(
            "fastapi",
            shape,
            size,
            inflight,
            statuses,
            cpu,
            wall,
            rss_before,
            len(body),
            tm,
        )

    return asyncio.run(main())


def cell_flask(shape: str, size: int, inflight: int, tm: _Tm) -> dict[str, object]:
    from flask import Flask, request
    from flaskapi_guard.extension import FlaskAPIGuard

    from guard_core.models import SecurityConfig

    app = Flask(__name__)

    @app.route("/up", methods=["POST"])
    def up() -> dict[str, int]:
        return {"n": len(request.get_data())}

    FlaskAPIGuard(
        app, config=SecurityConfig(**_config_kwargs(size, SecurityConfig.model_fields))
    )
    body, content_type = build_multipart(shape, size)
    headers = {"Content-Type": content_type, "X-Forwarded-For": "203.0.113.9"}
    app.test_client().post("/up", data=b"warm", headers=headers)
    rss_before = _rss_bytes()

    def call() -> int:
        response = app.test_client().post("/up", data=body, headers=headers)
        return _note_refusal(int(response.status_code), response.get_data(as_text=True))

    tm.start()
    statuses, cpu, wall = _threaded(call, inflight)
    return _report(
        "flask", shape, size, inflight, statuses, cpu, wall, rss_before, len(body), tm
    )


def cell_django(shape: str, size: int, inflight: int, tm: _Tm) -> dict[str, object]:
    import django
    from django.conf import settings

    from guard_core.models import SecurityConfig

    urlconf = types.ModuleType("multipart_cells_urls")
    sys.modules["multipart_cells_urls"] = urlconf
    settings.configure(
        SECRET_KEY="multipart-cells",
        ALLOWED_HOSTS=["*"],
        ROOT_URLCONF="multipart_cells_urls",
        MIDDLEWARE=["djangoapi_guard.middleware.DjangoAPIGuard"],
        GUARD_SECURITY_CONFIG=SecurityConfig(
            **_config_kwargs(size, SecurityConfig.model_fields)
        ),
        USE_TZ=True,
        DATA_UPLOAD_MAX_MEMORY_SIZE=None,
    )
    django.setup()
    from django.http import HttpRequest, JsonResponse
    from django.test import Client
    from django.urls import path

    def up(request: HttpRequest) -> JsonResponse:
        return JsonResponse({"n": len(request.body)})

    urlconf.__dict__["urlpatterns"] = [path("up", up)]
    body, content_type = build_multipart(shape, size)
    headers = {"X-Forwarded-For": "203.0.113.9"}
    Client().post("/up", data=b"warm", content_type="text/plain", headers=headers)
    rss_before = _rss_bytes()

    def call() -> int:
        response = Client().post(
            "/up", data=body, content_type=content_type, headers=headers
        )
        return _note_refusal(
            response.status_code, response.content.decode(errors="replace")
        )

    tm.start()
    statuses, cpu, wall = _threaded(call, inflight)
    return _report(
        "django", shape, size, inflight, statuses, cpu, wall, rss_before, len(body), tm
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=["cell"])
    parser.add_argument("reader", choices=("fastapi", "flask", "django"))
    parser.add_argument("shape", choices=("mp-flat", "mp-escaped", "mp-binary"))
    parser.add_argument("size", type=int)
    parser.add_argument("inflight", type=int)
    parser.add_argument("--tm", action="store_true")
    args = parser.parse_args()
    warnings.simplefilter("ignore")
    logging.disable(logging.CRITICAL)
    cells: dict[str, Callable[[str, int, int, _Tm], dict[str, object]]] = {
        "fastapi": cell_fastapi,
        "flask": cell_flask,
        "django": cell_django,
    }
    result = cells[args.reader](args.shape, args.size, args.inflight, _Tm(args.tm))
    result["pass"] = "B-tracemalloc" if args.tm else "A-rss-cpu-wall"
    print(json.dumps(result))


if __name__ == "__main__":
    main()
