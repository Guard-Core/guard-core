import threading

PROBE_DEADLINE_SECONDS = 0.25


def _ping_a_fresh_connection(url: str, answered: list[bool]) -> None:
    from redis import ConnectionPool, Redis
    from redis.backoff import NoBackoff
    from redis.connection import parse_url
    from redis.retry import Retry

    pool = None
    try:
        pool = ConnectionPool(
            **{
                **parse_url(url),
                "socket_connect_timeout": PROBE_DEADLINE_SECONDS,
                "socket_timeout": PROBE_DEADLINE_SECONDS,
                "retry": Retry(NoBackoff(), 0),
                "max_connections": 1,
            }
        )
        answered.append(bool(Redis(connection_pool=pool).ping()))
    except Exception:
        answered.append(False)
    finally:
        if pool is not None:
            pool.disconnect()


def redis_answers_within_the_deadline(url: str) -> bool:
    """Whether a Redis at ``url`` answers a PING to a fresh connection. A bare client
    (not the shared registry) with no retry; the connect, redis-py's connect handshake
    and the PING share one deadline, and the URL's own timeout params cannot stretch
    it. The caller waits at most the deadline; the ping thread closes its connection
    itself whatever happens."""
    answered: list[bool] = []
    worker = threading.Thread(
        target=_ping_a_fresh_connection,
        args=(url, answered),
        name="guard-core-redis-probe",
        daemon=True,
    )
    worker.start()
    worker.join(PROBE_DEADLINE_SECONDS)
    return not worker.is_alive() and answered == [True]
