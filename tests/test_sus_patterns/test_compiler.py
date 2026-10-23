import asyncio
import concurrent.futures
import re
import types
from typing import cast
from unittest.mock import MagicMock, patch

import pytest

from guard_core.detection_engine._redos_structure import (
    _detect_nested_unbounded_quantifier,
    _strip_escapes_and_char_classes,
)
from guard_core.detection_engine.compiler import PatternCompiler


def _fake_popen(returncode: int, stdout: str) -> MagicMock:
    process = MagicMock()
    process.returncode = returncode
    process.__enter__.return_value = process
    process.communicate.return_value = (stdout, "")
    return MagicMock(return_value=process)


@pytest.fixture
def compiler() -> PatternCompiler:
    return PatternCompiler(default_timeout=5.0, max_cache_size=100)


def test_initialization() -> None:
    compiler = PatternCompiler()
    assert compiler.default_timeout == 5.0
    assert compiler.max_cache_size == 1000
    assert len(compiler._compiled_cache) == 0
    assert len(compiler._cache_order) == 0

    compiler = PatternCompiler(default_timeout=10.0, max_cache_size=500)
    assert compiler.default_timeout == 10.0
    assert compiler.max_cache_size == 500

    compiler = PatternCompiler(max_cache_size=10000)
    assert compiler.max_cache_size == 5000


def test_compile_pattern_sync(compiler: PatternCompiler) -> None:
    pattern = r"test\d+"
    compiled = compiler.compile_pattern_sync(pattern)
    assert isinstance(compiled, re.Pattern)
    assert compiled.search("test123") is not None
    assert compiled.search("test") is None

    pattern = r"TEST\d+"
    compiled = compiler.compile_pattern_sync(pattern, flags=0)
    assert compiled.search("TEST123") is not None
    assert compiled.search("test123") is None


@pytest.mark.asyncio
async def test_compile_pattern_cache_hit(compiler: PatternCompiler) -> None:
    pattern = r"cached_pattern\d+"

    compiled1 = await compiler.compile_pattern(pattern)
    assert isinstance(compiled1, re.Pattern)

    compiled2 = await compiler.compile_pattern(pattern)
    assert compiled1 is compiled2

    cache_key = f"{pattern}:{re.IGNORECASE | re.MULTILINE}"
    assert cache_key in compiler._compiled_cache
    assert cache_key in compiler._cache_order
    assert compiler._cache_order[-1] == cache_key


@pytest.mark.asyncio
async def test_compile_pattern_cache_miss(compiler: PatternCompiler) -> None:
    compiler.max_cache_size = 3
    patterns = [f"pattern_{i}" for i in range(3)]

    for pattern in patterns:
        await compiler.compile_pattern(pattern)

    assert len(compiler._compiled_cache) == 3
    assert len(compiler._cache_order) == 3

    new_pattern = "pattern_new"
    await compiler.compile_pattern(new_pattern)

    assert len(compiler._compiled_cache) == 3
    assert len(compiler._cache_order) == 3

    first_key = f"{patterns[0]}:{re.IGNORECASE | re.MULTILINE}"
    assert first_key not in compiler._compiled_cache

    new_key = f"{new_pattern}:{re.IGNORECASE | re.MULTILINE}"
    assert new_key in compiler._compiled_cache


@pytest.mark.asyncio
async def test_compile_pattern_concurrent_access(compiler: PatternCompiler) -> None:
    pattern = r"concurrent_pattern"

    results = [await compiler.compile_pattern(pattern) for _ in range(10)]

    first_result = results[0]
    assert all(result is first_result for result in results)

    assert len(compiler._compiled_cache) == 1


def test_validate_pattern_safety_dangerous_patterns(compiler: PatternCompiler) -> None:
    dangerous_patterns = [
        r"(.*)+",
        r"(.+)+",
        r"([a-z]*)+",
        r"([a-z]+)+",
        r".*.*",
        r".+.+",
    ]

    for pattern in dangerous_patterns:
        is_safe, reason = compiler.validate_pattern_safety(pattern)
        assert is_safe is False
        assert "dangerous" in reason.lower()


def test_validate_pattern_safety_slow_pattern(compiler: PatternCompiler) -> None:
    slow_pattern = r"^[a-z]+$"

    fake_popen = _fake_popen(
        0, ('{"safe": false, "reason": "Pattern timed out on test string of length 5"}')
    )

    with patch(
        "guard_core.detection_engine._redos_limited_child.subprocess.Popen",
        new=fake_popen,
    ):
        is_safe, reason = compiler.validate_pattern_safety(
            slow_pattern, test_strings=["aaaaa"]
        )
        assert is_safe is False
        assert "timed out on test string" in reason


def test_validate_pattern_safety_exception(compiler: PatternCompiler) -> None:
    pattern = r"test_pattern"

    with patch.object(
        compiler, "compile_pattern_sync", side_effect=Exception("Test error")
    ):
        is_safe, reason = compiler.validate_pattern_safety(pattern)
        assert is_safe is False
        assert reason == "Pattern validation failed: Test error"


def test_validate_pattern_safety_safe_pattern(compiler: PatternCompiler) -> None:
    safe_patterns = [
        r"^[^>]*x",
        r"\d{3}-\d{3}-\d{4}",
        r"[a-zA-Z0-9]+",
        r"https?://[^\s]+",
    ]

    for pattern in safe_patterns:
        is_safe, reason = compiler.validate_pattern_safety(pattern)
        assert is_safe is True
        assert reason == "Pattern appears safe"


@pytest.mark.redos_timing
def test_validate_pattern_safety_rejects_unanchored_broad_scan_with_no_prefix() -> None:
    compiler = PatternCompiler()
    is_safe, reason = compiler.validate_pattern_safety(r"[^>]*x")
    assert is_safe is False, (
        "an unanchored broad scan with a missing terminator gives re.search a "
        "start position at every offset, each paying its own O(remaining) "
        f"backtrack search; this measures genuinely quadratic, got reason={reason}"
    )
    assert "extrapolated" in reason.lower(), reason


def test_validate_pattern_safety_accepts_unanchored_nested_star_group_shapes(
    compiler: PatternCompiler,
) -> None:
    unanchored_patterns = [
        r"(X*)*",
        r"(X+)*",
        r"(X*|Y)*",
        r"(?:X*)*",
        r"(?:X+)*",
        r"(a{2,})*",
    ]
    for pattern in unanchored_patterns:
        is_safe, reason = compiler.validate_pattern_safety(pattern)
        assert is_safe is True, (
            f"{pattern}: an outer-*-quantified group with nothing forcing "
            "failure afterward always has a trivial zero-repetition empty "
            f"match, so re.search never needs to backtrack; got {reason}"
        )


@pytest.mark.redos_timing
def test_validate_pattern_safety_rejects_nested_unbounded_quantifier_when_anchored(
    compiler: PatternCompiler,
) -> None:
    anchored_patterns = [
        r"(X*)*$",
        r"(X+)*$",
        r"(?:X*)*$",
        r"(?:X+)*$",
        r"(a{2,})*$",
    ]
    for pattern in anchored_patterns:
        is_safe, reason = compiler.validate_pattern_safety(pattern)
        assert is_safe is False, (
            f"{pattern}: the trailing $ forces exhaustive backtracking once "
            f"the trivial empty match no longer satisfies the pattern; {reason}"
        )


def test_validate_pattern_safety_rejects_brace_outer_dangerous_construct(
    compiler: PatternCompiler,
) -> None:
    is_safe, reason = compiler.validate_pattern_safety(r"(a*){2,}")
    assert is_safe is False
    assert "dangerous" in reason.lower()
    assert _detect_nested_unbounded_quantifier(r"(a*){2,}") is not None


def test_validate_pattern_safety_accepts_separator_anchored_groups(
    compiler: PatternCompiler,
) -> None:
    safe_patterns = [
        r"(?:[/\\][\w.\-~%]*)*",
        r"(?:[\w.\-~%]+[/\\])*",
        r"(?:[\w.\-~%]+[/\\][\w.\-~%]*)*",
        r"(a{2,4})*",
    ]
    for pattern in safe_patterns:
        nested = _detect_nested_unbounded_quantifier(pattern)
        assert nested is None, f"{pattern} falsely flagged: {nested}"


def test_detect_nested_unbounded_quantifier_helper() -> None:
    assert _detect_nested_unbounded_quantifier(r"(a*)*") is not None
    assert _detect_nested_unbounded_quantifier(r"(?:X+)*") is not None
    assert _detect_nested_unbounded_quantifier(r"(a{2,})*") is not None
    assert _detect_nested_unbounded_quantifier(r"(a*){2,}") is not None
    assert _detect_nested_unbounded_quantifier(r"(?P<n>a*)*") is not None
    assert _detect_nested_unbounded_quantifier(r"abc") is None
    assert _detect_nested_unbounded_quantifier(r"(unclosed") is None
    assert _detect_nested_unbounded_quantifier(r"(a*){2,4}") is None
    assert _detect_nested_unbounded_quantifier(r"(a*){") is None


def test_strip_escapes_and_char_classes_helper() -> None:
    assert _strip_escapes_and_char_classes(r"a") == "a"
    assert _strip_escapes_and_char_classes(r"\*") == "X"
    assert _strip_escapes_and_char_classes(r"[*+]") == "X"
    assert _strip_escapes_and_char_classes(r"[\[\]]") == "X"


def test_validate_pattern_safety_probe_subprocess_crash() -> None:
    compiler = PatternCompiler()

    pattern = r"test_pattern"

    def _raise(*args: object, **kwargs: object) -> None:
        raise OSError("no forkable subprocess slot")

    with patch(
        "guard_core.detection_engine._redos_limited_child.subprocess.Popen", _raise
    ):
        is_safe, reason = compiler.validate_pattern_safety(pattern, test_strings=["x"])

    assert is_safe is False
    assert "Pattern validation probe failed to run" in reason


def test_validate_pattern_safety_probe_subprocess_timeout() -> None:
    compiler = PatternCompiler()

    with (
        patch(
            "guard_core.detection_engine._redos_limited_child.subprocess.Popen",
            MagicMock(),
        ),
        patch(
            "guard_core.detection_engine._redos_limited_child.communicate_until_stalled",
            return_value=None,
        ),
    ):
        is_safe, reason = compiler.validate_pattern_safety(
            r"test_pattern", test_strings=["x"]
        )

    assert is_safe is False
    assert "killable-subprocess timeout" in reason


def test_validate_pattern_safety_probe_nonzero_returncode() -> None:
    compiler = PatternCompiler()

    fake_popen = _fake_popen(1, "")

    with patch(
        "guard_core.detection_engine._redos_limited_child.subprocess.Popen",
        new=fake_popen,
    ):
        is_safe, reason = compiler.validate_pattern_safety(
            r"test_pattern", test_strings=["x"]
        )

    assert is_safe is False
    assert "Pattern validation probe failed" in reason


def test_validate_pattern_safety_probe_malformed_output() -> None:
    compiler = PatternCompiler()

    fake_popen = _fake_popen(0, "not json")

    with patch(
        "guard_core.detection_engine._redos_limited_child.subprocess.Popen",
        new=fake_popen,
    ):
        is_safe, reason = compiler.validate_pattern_safety(
            r"test_pattern", test_strings=["x"]
        )

    assert is_safe is False
    assert "malformed output" in reason.lower()


def test_reach_probe_subprocess_crash_rejects_with_killable_subprocess_reason() -> None:
    compiler = PatternCompiler()

    def _raise(*args: object, **kwargs: object) -> None:
        raise OSError("no forkable subprocess slot")

    with patch(
        "guard_core.detection_engine._redos_limited_child.subprocess.Popen", _raise
    ):
        is_safe, reason = compiler.validate_pattern_safety(r"test_pattern")

    assert is_safe is False
    assert "killable-subprocess" in reason


def test_reach_probe_subprocess_nonzero_returncode_rejects() -> None:
    compiler = PatternCompiler()

    fake_popen = _fake_popen(1, "")

    with patch(
        "guard_core.detection_engine._redos_limited_child.subprocess.Popen",
        new=fake_popen,
    ):
        is_safe, reason = compiler.validate_pattern_safety(r"test_pattern")

    assert is_safe is False
    assert "killable-subprocess" in reason


def test_reach_probe_subprocess_malformed_output_rejects() -> None:
    compiler = PatternCompiler()

    fake_popen = _fake_popen(0, "not json")

    with patch(
        "guard_core.detection_engine._redos_limited_child.subprocess.Popen",
        new=fake_popen,
    ):
        is_safe, reason = compiler.validate_pattern_safety(r"test_pattern")

    assert is_safe is False
    assert "killable-subprocess" in reason


def test_validate_pattern_safety_fails_closed_when_probe_cannot_reach(
    compiler: PatternCompiler,
) -> None:
    is_safe, reason = compiler.validate_pattern_safety(r"(?P<n>a)(?P=n)")
    assert is_safe is False
    assert "could not construct a test string that reaches" in reason


def test_validate_pattern_safety_accepts_resolvable_numeric_backreference(
    compiler: PatternCompiler,
) -> None:
    is_safe, reason = compiler.validate_pattern_safety(r"(a)\1")
    assert is_safe is True, reason


def test_validate_pattern_safety_custom_test_strings(compiler: PatternCompiler) -> None:
    pattern = r"test\d+"
    test_strings = ["test123", "test456", "test789"]

    is_safe, reason = compiler.validate_pattern_safety(pattern, test_strings)
    assert is_safe is True
    assert reason == "Pattern appears safe"


def test_validate_pattern_safety_rejects_structural_violation_with_test_strings(
    compiler: PatternCompiler,
) -> None:
    pattern = r"(\w+\s?)*$"
    is_safe, reason = compiler.validate_pattern_safety(pattern, test_strings=["aaa"])
    assert is_safe is False
    assert "ambiguous optional tail" in reason.lower()


def test_create_safe_matcher(compiler: PatternCompiler) -> None:
    pattern = r"test\d+"
    matcher = compiler.create_safe_matcher(pattern)

    result = matcher("test123")
    assert result is not None
    assert result.group() == "test123"

    result = matcher("test")
    assert result is None


def test_create_safe_matcher_with_timeout(compiler: PatternCompiler) -> None:
    pattern = r"test.*"
    matcher = compiler.create_safe_matcher(pattern, timeout=0.1)

    with patch(
        "guard_core.detection_engine.compiler.shared_regex_executor"
    ) as mock_shared_executor:
        mock_future = MagicMock()
        mock_future.result.side_effect = concurrent.futures.TimeoutError()
        mock_future.cancel.return_value = True
        mock_shared_executor.return_value.submit.return_value = mock_future

        result = matcher("test123")
        assert result is None
        mock_future.cancel.assert_called_once()


def test_create_safe_matcher_with_exception(compiler: PatternCompiler) -> None:
    pattern = r"test.*"
    matcher = compiler.create_safe_matcher(pattern)

    with patch(
        "guard_core.detection_engine.compiler.shared_regex_executor"
    ) as mock_shared_executor:
        mock_future = MagicMock()
        mock_future.result.side_effect = Exception("Test error")
        mock_shared_executor.return_value.submit.return_value = mock_future

        result = matcher("test123")
        assert result is None


def test_create_safe_finditer_matcher_returns_all_matches(
    compiler: PatternCompiler,
) -> None:
    matcher = compiler.create_safe_finditer_matcher(r"cat")

    matches = matcher("cat cat cat")

    assert len(matches) == 3
    assert [m.group() for m in matches] == ["cat", "cat", "cat"]


def test_create_safe_finditer_matcher_no_match_returns_empty(
    compiler: PatternCompiler,
) -> None:
    matcher = compiler.create_safe_finditer_matcher(r"zzz")

    assert matcher("nothing here") == []


def test_create_safe_finditer_matcher_accepts_compiled_pattern(
    compiler: PatternCompiler,
) -> None:
    compiled = re.compile(r"hi", re.IGNORECASE)
    matcher = compiler.create_safe_finditer_matcher(compiled)

    matches = matcher("Hi hi HI")

    assert len(matches) == 3


def test_create_safe_finditer_matcher_timeout_returns_empty(
    compiler: PatternCompiler,
) -> None:
    matcher = compiler.create_safe_finditer_matcher(r"(a+)+$")

    with patch(
        "guard_core.detection_engine.compiler.shared_regex_executor"
    ) as mock_shared_executor:
        mock_future = MagicMock()
        mock_future.result.side_effect = concurrent.futures.TimeoutError()
        mock_shared_executor.return_value.submit.return_value = mock_future

        assert matcher("a" * 24 + "b") == []


def test_create_safe_finditer_matcher_exception_returns_empty(
    compiler: PatternCompiler,
) -> None:
    matcher = compiler.create_safe_finditer_matcher(r"test.*")

    with patch(
        "guard_core.detection_engine.compiler.shared_regex_executor"
    ) as mock_shared_executor:
        mock_future = MagicMock()
        mock_future.result.side_effect = Exception("Test error")
        mock_shared_executor.return_value.submit.return_value = mock_future

        assert matcher("test123") == []


def test_create_safe_finditer_matcher_uses_default_timeout() -> None:
    compiler = PatternCompiler(default_timeout=1.0)
    matcher = compiler.create_safe_finditer_matcher(r"hello")

    assert len(matcher("hello there hello")) == 2


def test_create_safe_matcher_inline_safe(compiler: PatternCompiler) -> None:
    matcher = compiler.create_safe_matcher(r"hello", inline_safe=True)

    match = matcher("hello world")
    assert match is not None
    assert match.group() == "hello"

    assert matcher("goodbye") is None


def test_create_safe_finditer_matcher_inline_safe(compiler: PatternCompiler) -> None:
    matcher = compiler.create_safe_finditer_matcher(r"cat", inline_safe=True)

    matches = matcher("cat cat cat")
    assert len(matches) == 3
    assert [m.group() for m in matches] == ["cat", "cat", "cat"]

    assert matcher("nothing") == []


@pytest.mark.asyncio
async def test_create_async_safe_finditer_matcher_inline_safe(
    compiler: PatternCompiler,
) -> None:
    matcher = compiler.create_async_safe_finditer_matcher(r"dog", inline_safe=True)

    matches = await matcher("dog dog")
    assert len(matches) == 2
    assert [m.group() for m in matches] == ["dog", "dog"]

    assert await matcher("nothing") == []


@pytest.mark.asyncio
async def test_create_async_safe_finditer_matcher_pool_timeout(
    compiler: PatternCompiler,
) -> None:
    matcher = compiler.create_async_safe_finditer_matcher(r"(a+)+$", timeout=0.05)

    with patch(
        "guard_core.detection_engine.compiler.shared_regex_executor"
    ) as mock_executor:
        mock_future = MagicMock()
        mock_future.result.side_effect = concurrent.futures.TimeoutError()
        mock_executor.return_value.submit.return_value = mock_future

        assert await matcher("a" * 24 + "b") == []


@pytest.mark.asyncio
async def test_create_async_safe_finditer_matcher_pool_success(
    compiler: PatternCompiler,
) -> None:
    matcher = compiler.create_async_safe_finditer_matcher(r"hello")

    matches = await matcher("hello world hello")
    assert len(matches) == 2
    assert [m.group() for m in matches] == ["hello", "hello"]


@pytest.mark.asyncio
async def test_batch_compile(compiler: PatternCompiler) -> None:
    patterns = [
        r"pattern1\d+",
        r"pattern2\w+",
        r"pattern3[a-z]+",
    ]

    compiled = await compiler.batch_compile(patterns, validate=False)
    assert len(compiled) == 3
    for pattern in patterns:
        assert pattern in compiled
        assert isinstance(compiled[pattern], re.Pattern)


@pytest.mark.asyncio
async def test_batch_compile_with_validation(compiler: PatternCompiler) -> None:
    patterns = [
        r"safe_pattern\d+",
        r"(.*)+",
        r"another_safe\w+",
    ]

    compiled = await compiler.batch_compile(patterns, validate=True)
    assert len(compiled) == 2
    assert patterns[0] in compiled
    assert patterns[1] not in compiled
    assert patterns[2] in compiled


@pytest.mark.asyncio
async def test_batch_compile_with_invalid_pattern(compiler: PatternCompiler) -> None:
    patterns = [
        r"valid_pattern",
        r"invalid(pattern",
        r"another_valid",
    ]

    compiled = await compiler.batch_compile(patterns, validate=False)
    assert len(compiled) == 2
    assert patterns[0] in compiled
    assert patterns[1] not in compiled
    assert patterns[2] in compiled


@pytest.mark.asyncio
async def test_clear_cache(compiler: PatternCompiler) -> None:
    patterns = ["pattern1", "pattern2", "pattern3"]
    for pattern in patterns:
        await compiler.compile_pattern(pattern)

    assert len(compiler._compiled_cache) == 3
    assert len(compiler._cache_order) == 3

    await compiler.clear_cache()

    assert len(compiler._compiled_cache) == 0
    assert len(compiler._cache_order) == 0


@pytest.mark.asyncio
async def test_clear_cache_thread_safety(compiler: PatternCompiler) -> None:
    await compiler.compile_pattern("pattern1")

    async def compile_task() -> None:
        await compiler.compile_pattern("pattern2")

    async def clear_task() -> None:
        await compiler.clear_cache()

    await asyncio.gather(compile_task(), clear_task(), return_exceptions=True)

    assert len(compiler._compiled_cache) == len(compiler._cache_order)


async def test_compile_pattern_handles_cache_race_between_outer_and_locked_check(
    compiler: PatternCompiler,
) -> None:
    # Simulate TOCTOU: outer `if cache_key in ...` is True, then cache is cleared
    # before we acquire the lock. Inner check is False, fall through to re-compile.
    pattern = r"race_me"
    cache_key = f"{pattern}:{re.IGNORECASE | re.MULTILINE}"
    compiler._compiled_cache[cache_key] = re.compile(pattern)
    compiler._cache_order.append(cache_key)

    real_lock = compiler._lock

    class _LockWrapper:
        async def __aenter__(self) -> "_LockWrapper":
            compiler._compiled_cache.pop(cache_key, None)
            if cache_key in compiler._cache_order:
                compiler._cache_order.remove(cache_key)
            await real_lock.__aenter__()
            return self

        async def __aexit__(
            self,
            exc_type: type[BaseException] | None,
            exc_val: BaseException | None,
            exc_tb: types.TracebackType | None,
        ) -> None:
            await real_lock.__aexit__(exc_type, exc_val, exc_tb)

    compiler._lock = cast(asyncio.Lock, _LockWrapper())
    compiled = await compiler.compile_pattern(pattern)
    assert compiled.pattern == pattern
    compiler._lock = real_lock


async def test_compile_pattern_returns_cached_entry_when_populated_during_lock_wait(
    compiler: PatternCompiler,
) -> None:
    # Outer `in self._compiled_cache` is False. Before we enter the second lock,
    # another coroutine populates the cache. Inner `not in` is False; return it.
    pattern = r"populated_during_wait"
    cache_key = f"{pattern}:{re.IGNORECASE | re.MULTILINE}"
    pre_compiled = re.compile(pattern)

    real_lock = compiler._lock
    state = {"seen_outer": False}

    class _LockWrapper:
        async def __aenter__(self) -> "_LockWrapper":
            if not state["seen_outer"]:
                state["seen_outer"] = True
                compiler._compiled_cache[cache_key] = pre_compiled
            await real_lock.__aenter__()
            return self

        async def __aexit__(
            self,
            exc_type: type[BaseException] | None,
            exc_val: BaseException | None,
            exc_tb: types.TracebackType | None,
        ) -> None:
            await real_lock.__aexit__(exc_type, exc_val, exc_tb)

    compiler._lock = cast(asyncio.Lock, _LockWrapper())
    result = await compiler.compile_pattern(pattern)
    assert result is pre_compiled
    compiler._lock = real_lock
