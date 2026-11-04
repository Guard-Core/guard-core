from cachetools import TTLCache

from guard_core.models import SyncSecurityConfig
from guard_core.sync.handlers.security_headers_handler import SecurityHeadersManager


class _CountingCache(TTLCache):
    def __init__(self) -> None:
        self.now = 0.0
        self.lookups: list[str] = []
        super().__init__(maxsize=10, ttl=300, timer=lambda: self.now)

    def get(self, key: object, default: object = None) -> object:
        self.lookups.append("get")
        return super().get(key, default)

    def __contains__(self, key: object) -> bool:
        self.lookups.append("contains")
        return super().__contains__(key)


def _manager(cache: TTLCache) -> SecurityHeadersManager:
    manager = SecurityHeadersManager.isolated()
    manager.headers_cache = cache
    return manager


def test_a_response_looks_its_headers_up_with_one_cache_read() -> None:
    cache = _CountingCache()
    manager = _manager(cache)
    config = SyncSecurityConfig(enable_redis=False)
    manager.get_headers("/a", config=config)
    cache.lookups.clear()

    manager.get_headers("/a", config=config)

    assert cache.lookups == []


def test_an_expired_entry_is_rebuilt() -> None:
    cache = _CountingCache()
    manager = _manager(cache)
    config = SyncSecurityConfig(enable_redis=False)
    first = manager.get_headers("/a", config=config)
    assert manager.get_headers("/a", config=config) is first

    cache.now = 301.0
    rebuilt = manager.get_headers("/a", config=config)

    assert rebuilt is not first
    assert rebuilt == first
