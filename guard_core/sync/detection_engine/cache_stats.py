from typing import TypedDict


class CacheStats(TypedDict):
    hits: int
    misses: int
    evictions: int
    size: int
    max_size: int | None
    hit_rate: float | None


def build_cache_stats(
    hits: int, misses: int, evictions: int, size: int, max_size: int | None
) -> CacheStats:
    lookups = hits + misses
    return {
        "hits": hits,
        "misses": misses,
        "evictions": evictions,
        "size": size,
        "max_size": max_size,
        "hit_rate": hits / lookups if lookups else None,
    }
