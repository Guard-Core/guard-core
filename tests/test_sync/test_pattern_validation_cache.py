"""Tests for the disk-backed pattern-validation cache."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from guard_core.models import SecurityConfig
from guard_core.sync.detection_engine import _validation_cache
from guard_core.sync.detection_engine._validation_cache import PatternValidationCache
from guard_core.sync.detection_engine.compiler import PatternCompiler
from guard_core.sync.handlers._suspatterns_state import _build_enhanced_detection_state


def _entry(safe: bool, reason: str) -> dict[str, object]:
    return {
        "safe": safe,
        "reason": reason,
        "version": _validation_cache.ENGINE_VERSION,
    }


def test_put_then_get_round_trips(tmp_path: Path) -> None:
    cache = PatternValidationCache(tmp_path / "cache.json")
    cache.put("a+", 0, True, "Pattern appears safe")
    assert cache.get("a+", 0) == (True, "Pattern appears safe")
    assert len(cache) == 1


def test_persisted_file_survives_a_new_instance(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    PatternValidationCache(path).put("(x+x+)+y", 0, False, "over budget")
    reopened = PatternValidationCache(path)
    assert reopened.get("(x+x+)+y", 0) == (False, "over budget")


def test_get_miss_returns_none(tmp_path: Path) -> None:
    cache = PatternValidationCache(tmp_path / "cache.json")
    assert cache.get("never-seen", 0) is None


def test_flags_are_part_of_the_key(tmp_path: Path) -> None:
    cache = PatternValidationCache(tmp_path / "cache.json")
    cache.put("x", 0, True, "safe under flag 0")
    assert cache.get("x", 8) is None


def test_version_mismatch_entries_are_dropped(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    stale = {"k": {"safe": True, "reason": "stale", "version": "0.0.1"}}
    path.write_text(json.dumps(stale), encoding="utf-8")
    cache = PatternValidationCache(path)
    assert len(cache) == 0
    assert cache.get("anything", 0) is None


def test_corrupt_cache_starts_empty_and_recovers(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    path.write_text("{not json", encoding="utf-8")
    cache = PatternValidationCache(path)
    assert len(cache) == 0
    cache.put("b+", 0, True, "ok")
    assert cache.get("b+", 0) == (True, "ok")
    reopened = PatternValidationCache(path)
    assert reopened.get("b+", 0) == (True, "ok")


def test_write_is_atomic_no_tmp_leftovers(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    cache = PatternValidationCache(path)
    cache.put("c+", 0, True, "ok")
    leftovers = [p for p in tmp_path.iterdir() if p.name != "cache.json"]
    assert leftovers == []
    assert json.loads(path.read_text(encoding="utf-8"))


def test_compiler_uses_the_cache_and_skips_the_cost_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "cache.json"
    warm = PatternValidationCache(path)
    default_flags = re.IGNORECASE | re.MULTILINE
    warm.put("hello world", default_flags, True, "Pattern appears safe")

    compiler = PatternCompiler(validation_cache=warm)

    def explode(*args: object, **kwargs: object) -> tuple[bool, str]:
        raise AssertionError("the empirical cost verdict must not run on a hit")

    monkeypatch.setattr(
        "guard_core.sync.detection_engine.compiler._reach_probe_cost_verdict", explode
    )
    safe, reason = compiler.validate_pattern_safety("hello world")
    assert safe is True
    assert reason == "Pattern appears safe"


def test_compiler_populates_the_cache_on_a_miss(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    cache = PatternValidationCache(path)
    compiler = PatternCompiler(validation_cache=cache)

    safe, _ = compiler.validate_pattern_safety(r"\d{3}-\d{4}", max_content_length=10000)
    assert safe is True
    assert len(cache) == 1
    reopened = PatternValidationCache(path)
    assert reopened.get(r"\d{3}-\d{4}", re.IGNORECASE | re.MULTILINE) is not None


def test_test_strings_mode_bypasses_the_cache(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    cache = PatternValidationCache(path)
    cache.put("hello", 0, True, "would be wrong to trust here")
    compiler = PatternCompiler(validation_cache=cache)
    safe, reason = compiler.validate_pattern_safety(
        "hello", test_strings=["hello world"]
    )
    assert safe is True
    assert reason == "Pattern appears safe"
    assert len(cache) == 1


def test_dangerous_constructs_are_checked_before_the_cache(
    tmp_path: Path,
) -> None:
    path = tmp_path / "cache.json"
    cache = PatternValidationCache(path)
    cache.put("(.*)+", 0, True, "poisoned entry")
    compiler = PatternCompiler(validation_cache=cache)
    safe, reason = compiler.validate_pattern_safety("(.*)+")
    assert safe is False
    assert reason.startswith("Pattern contains dangerous construct")


def test_state_builder_wires_the_cache_from_config(tmp_path: Path) -> None:
    config = SecurityConfig(
        detection_pattern_validation_cache_path=str(tmp_path / "cache.json")
    )
    state = _build_enhanced_detection_state(config)
    assert state.compiler is not None
    assert state.compiler._validation_cache is not None
    assert len(state.compiler._validation_cache) == 0


def test_state_builder_leaves_the_cache_off_by_default() -> None:
    state = _build_enhanced_detection_state(SecurityConfig())
    assert state.compiler is not None
    assert state.compiler._validation_cache is None


def test_missing_entry_shape_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    bad = {"k": {"version": _validation_cache.ENGINE_VERSION, "safe": "yes"}}
    path.write_text(json.dumps(bad), encoding="utf-8")
    cache = PatternValidationCache(path)
    assert len(cache) == 0


def test_entry_helper_matches_expected_shape() -> None:
    entry = _entry(True, "ok")
    assert entry["version"] == _validation_cache.ENGINE_VERSION


def test_engine_version_falls_back_when_the_package_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_missing(name: str) -> str:
        raise _validation_cache.PackageNotFoundError(name)

    monkeypatch.setattr(_validation_cache, "_version", raise_missing)
    assert _validation_cache._engine_version() == "unknown"


def test_engine_version_falls_back_on_unexpected_metadata_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_odd(name: str) -> str:
        raise RuntimeError("metadata backend exploded")

    monkeypatch.setattr(_validation_cache, "_version", raise_odd)
    assert _validation_cache._engine_version() == "unknown"


def test_unreadable_cache_path_starts_empty(tmp_path: Path) -> None:
    directory = tmp_path / "cache-dir"
    directory.mkdir()
    cache = PatternValidationCache(directory)
    assert len(cache) == 0
    cache.put("d+", 0, True, "ok")
    assert cache.get("d+", 0) == (True, "ok")


def test_save_failure_is_logged_and_never_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    cache = PatternValidationCache(tmp_path / "cache.json")

    def broken_replace(src: object, dst: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(_validation_cache.os, "replace", broken_replace)
    logger_name = "guard_core.sync.detection_engine._validation_cache"
    with caplog.at_level("WARNING", logger=logger_name):
        cache.put("e+", 0, True, "ok")
    assert any("write failed" in r.message for r in caplog.records)
    assert cache.get("e+", 0) == (True, "ok")


def test_non_object_cache_root_starts_empty(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    assert len(PatternValidationCache(path)) == 0


def test_non_object_cache_entry_rejects_the_whole_file(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    bad = {"k": "not-a-dict"}
    path.write_text(json.dumps(bad), encoding="utf-8")
    assert len(PatternValidationCache(path)) == 0


def test_entry_without_a_boolean_verdict_rejects_the_file(
    tmp_path: Path,
) -> None:
    path = tmp_path / "cache.json"
    bad = {"k": {"version": _validation_cache.ENGINE_VERSION, "reason": "x"}}
    path.write_text(json.dumps(bad), encoding="utf-8")
    assert len(PatternValidationCache(path)) == 0


def test_interrupted_write_cleans_the_tmp_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "cache.json"
    cache = PatternValidationCache(path)

    def interrupted_replace(src: object, dst: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(_validation_cache.os, "replace", interrupted_replace)
    with pytest.raises(KeyboardInterrupt):
        cache.put("f+", 0, True, "ok")
    leftovers = [p for p in tmp_path.iterdir() if p.name != "cache.json"]
    assert leftovers == []


def test_entry_without_a_string_reason_rejects_the_file(
    tmp_path: Path,
) -> None:
    path = tmp_path / "cache.json"
    bad = {"k": {"version": _validation_cache.ENGINE_VERSION, "safe": True}}
    path.write_text(json.dumps(bad), encoding="utf-8")
    assert len(PatternValidationCache(path)) == 0


def test_interrupted_write_tolerates_tmp_cleanup_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "cache.json"
    cache = PatternValidationCache(path)

    def interrupted_replace(src: object, dst: object) -> None:
        raise KeyboardInterrupt

    def failing_unlink(name: object) -> None:
        raise OSError("already gone")

    monkeypatch.setattr(_validation_cache.os, "replace", interrupted_replace)
    monkeypatch.setattr(_validation_cache.os, "unlink", failing_unlink)
    with pytest.raises(KeyboardInterrupt):
        cache.put("g+", 0, True, "ok")
