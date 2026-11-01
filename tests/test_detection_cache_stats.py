from pathlib import Path

import pytest

from guard_core.detection_engine._validation_cache import PatternValidationCache
from guard_core.detection_engine.compiler import PatternCompiler
from guard_core.handlers._suspatterns_linear_path import (
    linear_path_cache_stats,
    linear_path_finder,
)
from guard_core.handlers.suspatterns_handler import SusPatternsManager


async def test_compiled_pattern_cache_counts_hits_misses_and_evictions() -> None:
    compiler = PatternCompiler(max_cache_size=2)
    assert compiler.get_cache_stats() == {
        "hits": 0,
        "misses": 0,
        "evictions": 0,
        "size": 0,
        "max_size": 2,
        "hit_rate": None,
    }

    await compiler.compile_pattern("alpha")
    await compiler.compile_pattern("alpha")
    await compiler.compile_pattern("alpha")
    await compiler.compile_pattern("beta")
    await compiler.compile_pattern("gamma")

    assert compiler.get_cache_stats() == {
        "hits": 2,
        "misses": 3,
        "evictions": 1,
        "size": 2,
        "max_size": 2,
        "hit_rate": 0.4,
    }


async def test_clearing_the_compiled_pattern_cache_keeps_the_counters() -> None:
    compiler = PatternCompiler()
    await compiler.compile_pattern("alpha")
    await compiler.compile_pattern("alpha")
    await compiler.clear_cache()

    stats = compiler.get_cache_stats()
    assert (stats["hits"], stats["misses"], stats["size"]) == (1, 1, 0)


def test_pattern_validation_cache_counts_hits_and_misses(tmp_path: Path) -> None:
    cache = PatternValidationCache(tmp_path / "validation.json")
    assert cache.get_cache_stats()["hit_rate"] is None

    assert cache.get("a+b", 0, 100) is None
    cache.put("a+b", 0, 100, True, "ok")
    assert cache.get("a+b", 0, 100) == (True, "ok")
    assert cache.get("a+b", 0, 100) == (True, "ok")

    assert cache.get_cache_stats() == {
        "hits": 2,
        "misses": 1,
        "evictions": 0,
        "size": 1,
        "max_size": None,
        "hit_rate": pytest.approx(2 / 3),
    }


def test_linear_path_cache_reports_what_lru_cache_counted() -> None:
    import re

    before = linear_path_cache_stats()
    pattern = re.compile(r"(?:\.\./){3}etc", re.IGNORECASE)
    linear_path_finder(pattern)
    linear_path_finder(pattern)
    after = linear_path_cache_stats()

    assert after["hits"] + after["misses"] >= before["hits"] + before["misses"] + 2
    assert after["hits"] > before["hits"]
    assert after["max_size"] == 1024


async def test_a_configured_validation_cache_is_reported_by_the_compiler(
    tmp_path: Path,
) -> None:
    compiler = PatternCompiler()
    assert compiler.get_validation_cache_stats() is None
    cached = PatternCompiler(
        validation_cache=PatternValidationCache(tmp_path / "validation.json")
    )
    stats = cached.get_validation_cache_stats()
    assert stats is not None
    assert stats["hit_rate"] is None


async def test_performance_stats_carry_the_cache_hit_rates(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    manager = sus_patterns_manager_with_detection
    await manager.detect_pattern_match("<script>alert(1)</script>", "127.0.0.1", "t")

    stats = await manager.get_performance_stats()

    assert stats is not None
    caches = stats["caches"]
    assert set(caches) == {"compiled_patterns", "linear_path_patterns"}
    assert caches == await manager.get_cache_stats()
    for cache in caches.values():
        lookups = cache["hits"] + cache["misses"]
        assert cache["hit_rate"] == (cache["hits"] / lookups if lookups else None)


async def test_a_configured_validation_cache_appears_in_the_manager_stats(
    sus_patterns_manager_with_detection: SusPatternsManager, tmp_path: Path
) -> None:
    manager = sus_patterns_manager_with_detection
    compiler = manager._detection_state.compiler
    assert compiler is not None
    compiler.__dict__["_validation_cache"] = PatternValidationCache(
        tmp_path / "validation.json"
    )

    caches = await manager.get_cache_stats()

    assert set(caches) == {
        "compiled_patterns",
        "pattern_validation",
        "linear_path_patterns",
    }


async def test_a_manager_without_a_compiler_reports_only_the_linear_path_cache(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    manager = sus_patterns_manager_with_detection
    manager._compiler = None

    caches = await manager.get_cache_stats()

    assert set(caches) == {"linear_path_patterns"}
