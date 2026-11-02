import concurrent.futures

from guard_core.models import SyncSecurityConfig
from guard_core.sync._utils.access_control import is_user_agent_allowed
from guard_core.sync.detection_engine.compiler import PatternCompiler
from guard_core.sync.handlers.suspatterns_handler import (
    SusPatternsManager,
    scanning_with,
)


def test_blocked_user_agent_patterns_are_compiled_once_per_pattern_set(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    manager = sus_patterns_manager_with_detection
    config = SyncSecurityConfig(blocked_user_agents=["badbot", "evilcrawler"])
    compiler = manager._detection_state.compiler
    assert compiler is not None
    before = compiler.get_cache_stats()

    with scanning_with(manager):
        for _ in range(5):
            assert is_user_agent_allowed("Mozilla/5.0", config)
        assert not is_user_agent_allowed("a BADBOT crawler", config)

    after = compiler.get_cache_stats()
    assert after["misses"] - before["misses"] == 2
    assert after["hits"] - before["hits"] == 4 * 2 + 2
    assert (manager.get_cache_stats())["compiled_patterns"] == after


def test_user_agent_patterns_without_a_configured_compiler_share_one_cache(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    manager = sus_patterns_manager_with_detection
    manager._compiler = None
    config = SyncSecurityConfig(blocked_user_agents=["noncompiler-bot"])

    with scanning_with(manager):
        for _ in range(3):
            assert is_user_agent_allowed("Mozilla/5.0", config)

    from guard_core.sync._utils import user_agent_compiler

    shared = user_agent_compiler._fallback_user_agent_compiler
    assert shared is not None
    assert shared.get_cache_stats()["hits"] >= 2


def test_adding_a_pattern_compiles_it_once_for_validation_and_storage(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    manager = sus_patterns_manager_with_detection
    compiler = manager._detection_state.compiler
    assert compiler is not None
    before = compiler.get_cache_stats()

    assert manager.add_pattern(r"wiring-added-\d+", custom=True)

    after = compiler.get_cache_stats()
    assert after["misses"] - before["misses"] == 1
    assert after["hits"] - before["hits"] == 1


def test_compile_pattern_sync_serves_a_repeat_from_the_cache() -> None:
    compiler = PatternCompiler()

    first = compiler.compile_pattern_sync("sync-cached")
    second = compiler.compile_pattern_sync("sync-cached")

    assert first is second
    stats = compiler.get_cache_stats()
    assert (stats["hits"], stats["misses"], stats["size"]) == (1, 1, 1)


def test_the_sync_and_async_compile_paths_share_one_entry() -> None:
    compiler = PatternCompiler()

    from_sync = compiler.compile_pattern_sync("shared-entry")
    from_async = compiler.compile_pattern("shared-entry")

    assert from_sync is from_async
    assert compiler.get_cache_stats()["size"] == 1


def test_threads_compiling_together_keep_the_counters_exact() -> None:
    compiler = PatternCompiler(max_cache_size=8)
    patterns = [f"thread-{index}" for index in range(8)]

    def compile_all() -> None:
        for _ in range(200):
            for pattern in patterns:
                compiler.compile_pattern_sync(pattern)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for future in [pool.submit(compile_all) for _ in range(4)]:
            future.result()

    stats = compiler.get_cache_stats()
    assert stats["misses"] == 8
    assert stats["hits"] == 4 * 200 * 8 - 8
    assert stats["size"] == 8
    assert stats["evictions"] == 0


def test_a_pattern_set_is_compiled_once_and_every_repeat_counts_a_hit_per_pattern() -> (
    None
):
    compiler = PatternCompiler()
    patterns = ["set-alpha", "set-beta", "set-gamma"]

    first = compiler.compile_pattern_set_sync(patterns)
    second = compiler.compile_pattern_set_sync(list(patterns))

    assert second is first
    assert [pattern for pattern, _ in first] == patterns
    stats = compiler.get_cache_stats()
    assert (stats["hits"], stats["misses"]) == (3, 3)


def test_clearing_the_cache_drops_the_pattern_sets_and_the_bound_holds() -> None:
    compiler = PatternCompiler(max_cache_size=1)

    first = compiler.compile_pattern_set_sync(["bound-a"])
    compiler.compile_pattern_set_sync(["bound-b"])
    assert len(compiler._compiled_sets) == 1
    assert compiler.compile_pattern_set_sync(["bound-a"]) is not first

    compiler.clear_cache()
    assert not compiler._compiled_sets
