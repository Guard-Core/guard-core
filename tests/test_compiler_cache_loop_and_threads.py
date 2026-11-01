import asyncio

from guard_core.detection_engine.compiler import PatternCompiler


async def test_threads_and_the_loop_compiling_together_count_exactly() -> None:
    compiler = PatternCompiler(max_cache_size=8)
    patterns = [f"thread-{index}" for index in range(8)]

    def compile_all_in_a_thread() -> None:
        for _ in range(200):
            for pattern in patterns:
                compiler.compile_pattern_sync(pattern)

    async def compile_all_on_the_loop() -> None:
        for _ in range(200):
            for pattern in patterns:
                await compiler.compile_pattern(pattern)

    await asyncio.gather(
        asyncio.to_thread(compile_all_in_a_thread),
        asyncio.to_thread(compile_all_in_a_thread),
        compile_all_on_the_loop(),
    )

    stats = compiler.get_cache_stats()
    assert stats["misses"] == 8
    assert stats["hits"] == 3 * 200 * 8 - 8
    assert stats["size"] == 8
    assert stats["evictions"] == 0
