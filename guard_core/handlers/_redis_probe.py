import asyncio

PROBE_DEADLINE_SECONDS = 0.25


async def redis_answers_within_the_deadline(url: str) -> bool:
    """Whether a Redis at ``url`` answers a PING to a fresh connection. A bare client
    (not the shared registry) with no retry; the connect and the PING share one
    deadline, and the URL's own timeout params cannot stretch it. The connection is
    closed whatever happens, a cancel included."""
    from redis.asyncio import ConnectionPool, Redis
    from redis.asyncio.connection import parse_url
    from redis.asyncio.retry import Retry
    from redis.backoff import NoBackoff

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
        await asyncio.wait_for(
            Redis(connection_pool=pool).ping(), PROBE_DEADLINE_SECONDS
        )
        return True
    except Exception:
        return False
    finally:
        if pool is not None:
            await pool.disconnect()
