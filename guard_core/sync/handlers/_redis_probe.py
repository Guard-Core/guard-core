PROBE_DEADLINE_SECONDS = 0.25


def redis_answers_within_the_deadline(url: str) -> bool:
    """Whether a Redis at ``url`` answers a PING to a fresh connection. A bare client
    (not the shared registry) with no retry; the URL's own timeout params cannot
    stretch the deadline. The connection is closed whatever happens.

    shortcut: the connect and the PING each get the deadline, so a silent Redis that
    accepts slowly can take up to twice as long here, unlike the async twin's one
    shared deadline; upgrade when a sync caller needs the exact bound."""
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
        Redis(connection_pool=pool).ping()
        return True
    except Exception:
        return False
    finally:
        if pool is not None:
            pool.disconnect()
