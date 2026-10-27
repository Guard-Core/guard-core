import json
import multiprocessing
import os
from pathlib import Path

bind = "0.0.0.0:8000"


def _scenario_enables_redis() -> bool:
    path = os.environ.get("SMOKE_CONFIG_PATH", "")
    if not path or not Path(path).is_file():
        return True
    text = Path(path).read_text(encoding="utf-8").strip()
    return bool(json.loads(text).get("enable_redis", True)) if text else True


# Two workers share the scenario's Redis. A scenario that turns Redis off keeps its
# counters in process memory, which only one worker can hold, so it runs on one.
workers = (
    int(os.environ.get("WEB_CONCURRENCY", multiprocessing.cpu_count() * 2 + 1))
    if _scenario_enables_redis()
    else 1
)
worker_class = "uvicorn.workers.UvicornWorker"
timeout = 120
keepalive = 5
graceful_timeout = 30
max_requests = 1000
max_requests_jitter = 50

accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("LOG_LEVEL", "info")
