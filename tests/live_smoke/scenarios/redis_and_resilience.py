import subprocess
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

from tests.live_smoke.driver import PROJECT, STACK_DIR, ScenarioContext, wait_until
from tests.live_smoke.registry import scenario

REDIS_SERVICE = "redis"
EXCLUDED_HEADERS = ["x-real-ip", "x-forwarded-for"]


def _compose_signal(action: str) -> None:
    subprocess.run(
        [
            "docker",
            "compose",
            "-p",
            PROJECT,
            "-f",
            str(STACK_DIR / "compose.yml"),
            action,
            REDIS_SERVICE,
        ],
        cwd=STACK_DIR,
        capture_output=True,
        text=True,
        check=True,
    )


@contextmanager
def _redis_paused() -> Iterator[None]:
    _compose_signal("pause")
    try:
        yield
    finally:
        _compose_signal("unpause")


POOL_TUNING_CONFIG = {
    "enable_redis": True,
    "redis_prefix": "smoke_pool_test:",
    "redis_max_connections": 5,
    "redis_retries": 2,
    "redis_health_check_interval": 10,
    "lazy_init": True,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(
    covers={
        "enable_redis",
        "redis_prefix",
        "redis_max_connections",
        "redis_retries",
        "redis_health_check_interval",
        "lazy_init",
    },
    config=POOL_TUNING_CONFIG,
)
def redis_prefix_and_pool_tuning_survive_normal_operation(
    ctx: ScenarioContext,
) -> None:
    basic = ctx.client.get("/basic/ip", params={"q": "hello"})
    assert basic.status_code == 200

    keys = wait_until(lambda: ctx.redis.keys("smoke_pool_test:*") or None, timeout=10.0)
    assert keys, "redis_prefix should namespace at least one written Redis key"


POOL_BURST_CONFIG = {
    "enable_redis": True,
    "redis_prefix": "smoke_pool_burst:",
    "redis_max_connections": 3,
    "redis_pool_timeout": 5.0,
    "enable_rate_limiting": True,
    "rate_limit": 100000,
    "rate_limit_window": 60,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(covers={"redis_pool_timeout"}, config=POOL_BURST_CONFIG)
def a_burst_above_the_redis_pool_waits_instead_of_failing(
    ctx: ScenarioContext,
) -> None:
    # The burst measures the guard's pool wait, so it must not meet nginx's own
    # 30 r/s limit (a fast app lets 40 threads exceed it and nginx answers 503).
    def hit(_: int) -> int:
        return ctx.client.get(
            "/basic/ip",
            params={"q": "hello"},
            headers={"X-Smoke-Unlimited": "1"},
        ).status_code

    with ThreadPoolExecutor(max_workers=40) as executor:
        statuses = list(executor.map(hit, range(120)))

    assert statuses == [200] * 120, sorted(set(statuses))


FAIL_SECURE_CONFIG = {
    "fail_secure": True,
    "redis_fail_open": False,
    "redis_socket_timeout": 1.0,
    "redis_socket_connect_timeout": 1.0,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(
    covers={"fail_secure", "redis_socket_timeout", "redis_socket_connect_timeout"},
    config=FAIL_SECURE_CONFIG,
)
def redis_fail_secure_blocks_when_redis_is_paused(ctx: ScenarioContext) -> None:
    mark = ctx.stack.logs.mark()

    with _redis_paused():
        start = time.monotonic()
        response = ctx.client.get("/basic/ip", params={"q": "hello"})
        elapsed = time.monotonic() - start

        assert response.status_code == 503, (
            "fail_secure=True with redis_fail_open=False must block the request "
            f"when Redis is unreachable; got {response.status_code}"
        )
        assert response.headers.get("Retry-After") == "5", (
            "a Redis outage under fail_secure answers 503 with Retry-After: 5 "
            f"(D-188); got {response.headers.get('Retry-After')!r}"
        )
        assert elapsed < 8.0, (
            "redis_socket_timeout=1.0/redis_socket_connect_timeout=1.0 should "
            f"bound the failure detection; observed {elapsed:.2f}s"
        )

    log_text = "\n".join(ctx.stack.logs.lines_since(mark))
    assert "Blocking request due to check error in fail-secure mode" in log_text

    recovered = wait_until(
        lambda: ctx.client.get("/basic/ip", params={"q": "hello"}).status_code == 200,
        timeout=15.0,
    )
    assert recovered, "the app never recovered after Redis was unpaused"


FAIL_OPEN_CONFIG = {
    "redis_fail_open": True,
    "redis_socket_timeout": 1.0,
    "redis_socket_connect_timeout": 1.0,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(covers={"redis_fail_open"}, config=FAIL_OPEN_CONFIG)
def redis_fail_open_passes_through_when_redis_is_paused(
    ctx: ScenarioContext,
) -> None:
    mark = ctx.stack.logs.mark()

    with _redis_paused():
        start = time.monotonic()
        response = ctx.client.get("/basic/ip", params={"q": "hello"})
        elapsed = time.monotonic() - start

        assert response.status_code == 200, (
            "redis_fail_open=True must let the request through when Redis is "
            f"unreachable; got {response.status_code}"
        )
        assert elapsed < 8.0, (
            "redis_socket_timeout=1.0/redis_socket_connect_timeout=1.0 should "
            f"bound the failure detection; observed {elapsed:.2f}s"
        )

    log_text = "\n".join(ctx.stack.logs.lines_since(mark))
    assert "redis_fail_open=True" in log_text

    recovered = wait_until(
        lambda: ctx.client.get("/basic/ip", params={"q": "hello"}).status_code == 200,
        timeout=15.0,
    )
    assert recovered, "the app never recovered after Redis was unpaused"
