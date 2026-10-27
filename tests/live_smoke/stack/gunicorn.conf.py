import json
import multiprocessing
import os
from pathlib import Path

bind = "0.0.0.0:8000"


def _scenario_config() -> dict[str, object]:
    path = os.environ.get("SMOKE_CONFIG_PATH", "")
    if not path or not Path(path).is_file():
        return {}
    text = Path(path).read_text(encoding="utf-8").strip()
    return json.loads(text) if text else {}


def _worker_count(scenario_config: dict[str, object]) -> int:
    # Two workers share the scenario's Redis. A scenario that turns Redis off keeps
    # its counters in process memory, which only one worker can hold, and one that
    # counts per-process events (an event sent once per process) asks for one with
    # "smoke_workers".
    if "smoke_workers" in scenario_config:
        return int(str(scenario_config["smoke_workers"]))
    if scenario_config.get("enable_redis", True) is False:
        return 1
    return int(os.environ.get("WEB_CONCURRENCY", multiprocessing.cpu_count() * 2 + 1))


workers = _worker_count(_scenario_config())
worker_class = "uvicorn.workers.UvicornWorker"
timeout = 120
keepalive = 5
graceful_timeout = 30
max_requests = 1000
max_requests_jitter = 50

accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("LOG_LEVEL", "info")
