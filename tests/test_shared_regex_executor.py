import concurrent.futures
import re
import time
from typing import Any

import pytest

from guard_core.detection_engine import compiler as compiler_module
from guard_core.detection_engine.compiler import (
    PatternCompiler,
    shared_regex_executor,
)
from guard_core.handlers.suspatterns_handler import _CTX_ALL, SusPatternsManager
from guard_core.models import SecurityConfig


def test_shared_regex_executor_is_a_singleton() -> None:
    assert shared_regex_executor() is shared_regex_executor()


def test_validate_pattern_safety_never_touches_shared_scan_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FailIfUsed:
        def submit(self, *args: object, **kwargs: object) -> None:
            raise AssertionError("shared scan pool used during validation")

    monkeypatch.setattr(compiler_module, "shared_regex_executor", _FailIfUsed)

    pc = PatternCompiler()
    is_safe, reason = pc.validate_pattern_safety("hello", test_strings=["hi there"])

    assert is_safe is True
    assert reason == "Pattern appears safe"


class _FakeTimeoutFuture:
    def result(self, timeout: float = 0) -> None:
        raise concurrent.futures.TimeoutError()

    def cancel(self) -> None:
        pass


class _FakeTimeoutExecutor:
    def submit(self, fn: object, *args: object) -> "_FakeTimeoutFuture":
        return _FakeTimeoutFuture()

    def shutdown(self, wait: bool = True) -> None:
        pass


def test_poisoned_shared_pool_is_replaced_and_scans_work_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stale_executor = _FakeTimeoutExecutor()
    monkeypatch.setattr(compiler_module, "_shared_executor", stale_executor)
    monkeypatch.setattr(compiler_module, "_consecutive_timeouts", 0)

    pc = PatternCompiler()
    poisoned_matcher = pc.create_safe_matcher("x", timeout=0.01)

    for _ in range(compiler_module._SHARED_EXECUTOR_MAX_WORKERS):
        assert poisoned_matcher("anything") is None

    assert compiler_module._shared_executor is not stale_executor
    assert compiler_module._consecutive_timeouts == 0

    recovered_matcher = pc.create_safe_matcher("hello")
    assert recovered_matcher("say hello") is not None


def test_consecutive_timeout_counter_resets_on_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(compiler_module, "_consecutive_timeouts", 3)

    pc = PatternCompiler()
    matcher = pc.create_safe_matcher("hello")

    assert matcher("say hello") is not None
    assert compiler_module._consecutive_timeouts == 0


def test_safe_matcher_times_out_on_catastrophic_pattern() -> None:
    compiler = PatternCompiler()
    matcher = compiler.create_safe_matcher(r"(a+)+$", timeout=0.05)
    assert matcher("a" * 24 + "b") is None


def test_timeout_does_not_bound_a_gil_holding_catastrophic_match() -> None:
    compiler = PatternCompiler()
    matcher = compiler.create_safe_matcher(r"(?:a+)+$", timeout=0.3)
    subject = "a" * 27 + "!"

    start = time.monotonic()
    result = matcher(subject)
    elapsed = time.monotonic() - start

    assert result is None
    assert elapsed > 1.0, (
        f"a configured 0.3s timeout bounded a GIL-holding catastrophic regex "
        f"match to {elapsed:.3f}s. CPython's sre engine does not release the "
        f"GIL while matching, so future.result(timeout=...) cannot make the "
        f"waiting thread observe its own timeout until the match itself "
        f"finishes; shared_regex_executor()/create_safe_matcher only bound a "
        f"call whose regex work periodically releases the GIL (multiple "
        f"short matches, not one long one). If this assertion starts "
        f"failing, either the interpreter changed sre's GIL behavior or the "
        f"pattern was swapped for one from a module that genuinely releases "
        f"the GIL during matching (for example the third-party regex "
        f"module's own timeout= argument), and the timeout executor can "
        f"then be trusted as a real ReDoS bound again."
    )


def test_safe_matcher_still_works_after_a_timeout() -> None:
    compiler = PatternCompiler()
    slow = compiler.create_safe_matcher(r"(a+)+$", timeout=0.05)
    slow("a" * 24 + "b")
    fast = compiler.create_safe_matcher(r"abc")
    assert fast("xxabcxx") is not None


@pytest.fixture
def fresh_manager() -> Any:
    saved_instance = SusPatternsManager._instance
    saved_config = SusPatternsManager._config

    SusPatternsManager._instance = None
    manager = SusPatternsManager()
    manager.configure(SecurityConfig())
    yield manager

    SusPatternsManager._instance = saved_instance
    SusPatternsManager._config = saved_config


async def test_builtin_category_uses_safe_finditer_matcher(
    fresh_manager: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[Any] = []
    real = fresh_manager._compiler.create_async_safe_finditer_matcher

    def _tracking(
        pattern: Any,
        timeout: float | None = None,
        inline_safe: bool = False,
        worker_wrapper: Any = None,
    ) -> Any:
        calls.append(pattern)
        return real(
            pattern, timeout, inline_safe=inline_safe, worker_wrapper=worker_wrapper
        )

    monkeypatch.setattr(
        fresh_manager._compiler,
        "create_async_safe_finditer_matcher",
        _tracking,
    )
    pattern = re.compile(r"<script", re.IGNORECASE)

    threat, timed_out = await fresh_manager._check_regex_pattern(
        pattern, "<script>alert(1)</script>", "1.2.3.4", time.time(), "xss"
    )

    assert threat is not None
    assert timed_out is False
    assert calls == [pattern]


async def test_custom_category_uses_safe_finditer_matcher(
    fresh_manager: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[Any] = []
    real = fresh_manager._compiler.create_async_safe_finditer_matcher

    def _tracking(
        pattern: Any,
        timeout: float | None = None,
        inline_safe: bool = False,
        worker_wrapper: Any = None,
    ) -> Any:
        calls.append(pattern)
        return real(
            pattern, timeout, inline_safe=inline_safe, worker_wrapper=worker_wrapper
        )

    monkeypatch.setattr(
        fresh_manager._compiler,
        "create_async_safe_finditer_matcher",
        _tracking,
    )
    pattern = re.compile(r"evil")

    threat, _ = await fresh_manager._check_regex_pattern(
        pattern, "so evil", "1.2.3.4", time.time(), "custom"
    )

    assert threat is not None
    assert calls == [pattern]


async def test_pattern_timeout_on_custom_category_is_reported_as_a_threat(
    fresh_manager: Any,
) -> None:
    fresh_manager.configure(SecurityConfig(detection_compiler_timeout=0.1))
    slow_pattern = re.compile(r"(a+)+$")
    fresh_manager.compiled_custom_patterns.add((slow_pattern, _CTX_ALL, "custom"))

    result = await fresh_manager.detect(
        content="a" * 24 + "!",
        ip_address="1.2.3.4",
        context="unknown",
        correlation_id="test",
    )

    assert result["is_threat"] is True
    timeout_threats = [t for t in result["threats"] if t["type"] == "pattern_timeout"]
    assert timeout_threats
    assert timeout_threats[0]["pattern"] == slow_pattern.pattern


async def test_normal_input_stays_clean_after_the_timeout_fix(
    fresh_manager: Any,
) -> None:
    fresh_manager.configure(SecurityConfig(detection_compiler_timeout=0.1))
    slow_pattern = re.compile(r"(a+)+$")
    fresh_manager.compiled_custom_patterns.add((slow_pattern, _CTX_ALL, "custom"))

    result = await fresh_manager.detect(
        content="just a normal comment, nothing to see here",
        ip_address="1.2.3.4",
        context="unknown",
        correlation_id="test",
    )

    assert result["is_threat"] is False


async def test_custom_category_timeout_heuristic_ignores_wall_clock_jump(
    fresh_manager: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "guard_core.handlers.suspatterns_handler.time.time", lambda: 5_000.0
    )
    monkeypatch.setattr(
        "guard_core.handlers.suspatterns_handler.time.monotonic", lambda: 100.01
    )
    pattern_start = 100.0
    pattern = re.compile(r"zzz_never_matches_zzz")

    _, timed_out = await fresh_manager._check_regex_pattern(
        pattern, "no match in here", "1.2.3.4", pattern_start, "custom"
    )

    assert timed_out is False
