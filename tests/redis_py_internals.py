"""Which redis-py releases carry the internals the fast Redis path reads.

The fast path asks for each one on the slow path and falls back to the plain
release where it is missing, so the shape guards assert the internal where this
table says redis-py has it (the lock included) and the fallback where it does
not. The first releases come from reading every wheel from 5.0.0 to 8.1.0.
"""

from redis import __version__

_VERSION = tuple(int(part) for part in __version__.split(".")[:3])

# redis.event (the release event, its re-authentication listener), the
# connection pool's event dispatcher and Connection._re_auth_token
RELEASE_EVENTS_EXIST = _VERSION >= (5, 3, 0)
# Connection.should_reconnect
SHOULD_RECONNECT_EXISTS = _VERSION >= (7, 0, 0)
# redis.observability.recorder.record_connection_wait_time
WAIT_RECORDER_EXISTS = _VERSION >= (7, 3, 0)
# record_connection_count and the observability singleton the fast path reads
COUNT_RECORDER_EXISTS = _VERSION >= (7, 4, 0)
# EventDispatcher.register_listeners
REGISTER_LISTENERS_EXISTS = _VERSION >= (7, 0, 0)
# EventDispatcher.unregister_listeners
UNREGISTER_LISTENERS_EXISTS = _VERSION >= (8, 0, 0)
