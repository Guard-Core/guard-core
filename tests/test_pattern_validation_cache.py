"""Tests for the disk-backed pattern-validation cache."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from guard_core.detection_engine import _validation_cache
from guard_core.detection_engine._redos_cost_arbiter import TransientReason
from guard_core.detection_engine._validation_cache import PatternValidationCache
from guard_core.detection_engine.compiler import PatternCompiler
from guard_core.handlers._suspatterns_state import _build_enhanced_detection_state
from guard_core.models import SecurityConfig

CAP = 10000
DEFAULT_CAP = 262144


def _entry(safe: bool, reason: str) -> dict[str, object]:
    return {
        "safe": safe,
        "reason": reason,
        "version": _validation_cache.ENGINE_VERSION,
        "validator": _validation_cache._validator_tag(),
    }


def test_put_then_get_round_trips(tmp_path: Path) -> None:
    cache = PatternValidationCache(tmp_path / "cache.json")
    cache.put("a+", 0, CAP, True, "Pattern appears safe")
    assert cache.get("a+", 0, CAP) == (True, "Pattern appears safe")
    assert len(cache) == 1


def test_persisted_file_survives_a_new_instance(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    PatternValidationCache(path).put("(x+x+)+y", 0, CAP, False, "over budget")
    reopened = PatternValidationCache(path)
    assert reopened.get("(x+x+)+y", 0, CAP) == (False, "over budget")


def test_get_miss_returns_none(tmp_path: Path) -> None:
    cache = PatternValidationCache(tmp_path / "cache.json")
    assert cache.get("never-seen", 0, CAP) is None


def test_flags_are_part_of_the_key(tmp_path: Path) -> None:
    cache = PatternValidationCache(tmp_path / "cache.json")
    cache.put("x", 0, CAP, True, "safe under flag 0")
    assert cache.get("x", 8, CAP) is None


def test_version_mismatch_entries_are_dropped(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    stale = {"k": {"safe": True, "reason": "stale", "version": "0.0.1"}}
    path.write_text(json.dumps(stale), encoding="utf-8")
    cache = PatternValidationCache(path)
    assert len(cache) == 0
    assert cache.get("anything", 0, CAP) is None


def test_corrupt_cache_starts_empty_and_recovers(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    path.write_text("{not json", encoding="utf-8")
    cache = PatternValidationCache(path)
    assert len(cache) == 0
    cache.put("b+", 0, CAP, True, "ok")
    assert cache.get("b+", 0, CAP) == (True, "ok")
    reopened = PatternValidationCache(path)
    assert reopened.get("b+", 0, CAP) == (True, "ok")


def test_write_is_atomic_no_tmp_leftovers(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    cache = PatternValidationCache(path)
    cache.put("c+", 0, CAP, True, "ok")
    leftovers = [p for p in tmp_path.iterdir() if p.name != "cache.json"]
    assert leftovers == []
    assert json.loads(path.read_text(encoding="utf-8"))


def test_compiler_uses_the_cache_and_skips_the_cost_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "cache.json"
    warm = PatternValidationCache(path)
    default_flags = re.IGNORECASE | re.MULTILINE
    warm.put("hello world", default_flags, DEFAULT_CAP, True, "Pattern appears safe")

    compiler = PatternCompiler(validation_cache=warm)

    def explode(*args: object, **kwargs: object) -> tuple[bool, str]:
        raise AssertionError("the empirical cost verdict must not run on a hit")

    monkeypatch.setattr(
        "guard_core.detection_engine.compiler._reach_probe_cost_verdict", explode
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
    assert reopened.get(r"\d{3}-\d{4}", re.IGNORECASE | re.MULTILINE, 10000) is not None


def test_test_strings_mode_bypasses_the_cache(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    cache = PatternValidationCache(path)
    cache.put("hello", 0, CAP, True, "would be wrong to trust here")
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
    cache.put("(.*)+", 0, CAP, True, "poisoned entry")
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
    bad = {"k": {**_entry(True, "x"), "safe": "yes"}}
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
    cache.put("d+", 0, CAP, True, "ok")
    assert cache.get("d+", 0, CAP) == (True, "ok")


def test_save_failure_is_logged_and_never_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    cache = PatternValidationCache(tmp_path / "cache.json")

    def broken_replace(src: object, dst: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(_validation_cache.os, "replace", broken_replace)
    logger_name = "guard_core.detection_engine._validation_cache"
    with caplog.at_level("WARNING", logger=logger_name):
        cache.put("e+", 0, CAP, True, "ok")
    assert any("write failed" in r.message for r in caplog.records)
    assert cache.get("e+", 0, CAP) == (True, "ok")


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
    bad = {"k": {key: v for key, v in _entry(True, "x").items() if key != "safe"}}
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
        cache.put("f+", 0, CAP, True, "ok")
    leftovers = [p for p in tmp_path.iterdir() if p.name != "cache.json"]
    assert leftovers == []


def test_entry_without_a_string_reason_rejects_the_file(
    tmp_path: Path,
) -> None:
    path = tmp_path / "cache.json"
    bad = {"k": {key: v for key, v in _entry(True, "x").items() if key != "reason"}}
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
        cache.put("g+", 0, CAP, True, "ok")


DEFAULT_FLAGS = re.IGNORECASE | re.MULTILINE


def _cached_verdict(
    cache: PatternValidationCache, pattern: str, cap: int
) -> tuple[bool, str] | None:
    return cache.get(pattern, DEFAULT_FLAGS, cap)


def test_a_verdict_cached_at_one_cap_is_not_served_at_another(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def verdict(
        pattern: str,
        max_content_length: int | None,
        flags: int = 0,
        redaction_names: object = None,
    ) -> tuple[bool, str]:
        accepted = max_content_length is not None and max_content_length <= 512
        return accepted, "accepted at a small cap" if accepted else "over budget"

    monkeypatch.setattr(
        "guard_core.detection_engine.compiler._reach_probe_cost_verdict", verdict
    )
    cache = PatternValidationCache(tmp_path / "cache.json")
    compiler = PatternCompiler(validation_cache=cache)
    assert compiler.validate_pattern_safety("abc", max_content_length=512)[0] is True
    assert (
        compiler.validate_pattern_safety("abc", max_content_length=262144)[0] is False
    )
    assert compiler.validate_pattern_safety("abc", max_content_length=512)[0] is True


def test_a_none_cap_is_keyed_as_the_default_cap(tmp_path: Path) -> None:
    cache = PatternValidationCache(tmp_path / "cache.json")
    compiler = PatternCompiler(validation_cache=cache)
    compiler.validate_pattern_safety("abc")
    assert _cached_verdict(cache, "abc", DEFAULT_CAP) is not None
    assert _cached_verdict(cache, "abc", CAP) is None


def test_a_changed_validator_or_interpreter_misses_and_is_dropped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "cache.json"
    PatternValidationCache(path).put("abc", 0, CAP, True, "ok")
    monkeypatch.setattr(_validation_cache, "_validator_tag", lambda: "cpython-9:x")
    reopened = PatternValidationCache(path)
    assert len(reopened) == 0
    assert reopened.get("abc", 0, CAP) is None


def test_a_changed_engine_version_misses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "cache.json"
    PatternValidationCache(path).put("abc", 0, CAP, True, "ok")
    monkeypatch.setattr(_validation_cache, "_cached_engine_version", lambda: "0.0.0-x")
    reopened = PatternValidationCache(path)
    assert len(reopened) == 0
    assert reopened.get("abc", 0, CAP) is None


def test_engine_version_still_reads_the_installed_version() -> None:
    assert _validation_cache.ENGINE_VERSION == importlib.metadata.version("guard-core")


def test_an_unknown_module_attribute_still_raises() -> None:
    with pytest.raises(AttributeError):
        _ = _validation_cache.NOT_A_NAME


def test_importing_the_module_does_not_look_up_the_version() -> None:
    probe = (
        "import importlib.metadata as m\n"
        "import sys\n"
        "calls = []\n"
        "real = m.version\n"
        "import traceback\n"
        "def spy(name):\n"
        "    stack = traceback.extract_stack()\n"
        "    calls.extend(f for f in stack if '_validation_cache' in f.filename)\n"
        "    return real(name)\n"
        "m.version = spy\n"
        "import guard_core\n"
        f"import {_validation_cache.__name__}\n"
        "sys.exit(len(calls))\n"
    )
    done = subprocess.run([sys.executable, "-I", "-c", probe], check=False)
    assert done.returncode == 0


def test_the_validator_tag_names_the_interpreter_and_the_package_sources() -> None:
    tag = _validation_cache._validator_tag()
    assert tag.startswith(f"{sys.implementation.name}-")
    package_dir = Path(_validation_cache.__file__).parent
    assert tag.endswith(_validation_cache._validator_fingerprint(package_dir))


def test_changing_any_one_validator_file_changes_the_fingerprint(
    tmp_path: Path,
) -> None:
    package_dir = Path(_validation_cache.__file__).parent
    for source in package_dir.glob("*.py"):
        (tmp_path / source.name).write_bytes(source.read_bytes())
    baseline = _validation_cache._validator_fingerprint(tmp_path)
    assert baseline == _validation_cache._validator_fingerprint(package_dir)
    seen = {baseline}
    for source in sorted(tmp_path.glob("*.py")):
        original = source.read_bytes()
        source.write_bytes(original + b"\n# changed\n")
        seen.add(_validation_cache._validator_fingerprint(tmp_path))
        source.write_bytes(original)
    assert len(seen) == len(list(tmp_path.glob("*.py"))) + 1


def test_the_fingerprint_is_not_computed_by_importing_the_package() -> None:
    probe = (
        "import importlib, sys\n"
        "import guard_core\n"
        f"m = importlib.import_module({_validation_cache.__name__!r})\n"
        "sys.exit(m._validator_tag.cache_info().currsize)\n"
    )
    done = subprocess.run([sys.executable, "-I", "-c", probe], check=False)
    assert done.returncode == 0


def test_the_fingerprint_is_computed_once_when_the_first_cache_is_built(
    tmp_path: Path,
) -> None:
    _validation_cache._validator_tag.cache_clear()
    PatternValidationCache(tmp_path / "a.json")
    PatternValidationCache(tmp_path / "b.json")
    assert _validation_cache._validator_tag.cache_info().misses == 1


def test_a_cache_hit_spawns_no_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = PatternValidationCache(tmp_path / "cache.json")
    cache.put("abc", DEFAULT_FLAGS, DEFAULT_CAP, True, "Pattern appears safe")

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("a cache hit must not spawn or measure")

    monkeypatch.setattr("subprocess.run", refuse)
    monkeypatch.setattr(
        "guard_core.detection_engine._redos_cost_arbiter._measure_host_load_factor",
        refuse,
    )
    compiler = PatternCompiler(validation_cache=cache)
    assert compiler.validate_pattern_safety("abc") == (True, "Pattern appears safe")


def test_an_unreadable_validator_source_gets_its_own_fingerprint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken(self: Path) -> bytes:
        raise OSError("gone")

    monkeypatch.setattr(Path, "read_bytes", broken)
    package_dir = Path(_validation_cache.__file__).parent
    assert _validation_cache._validator_fingerprint(package_dir) == "unreadable"


def test_a_transient_reject_is_never_stored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = PatternValidationCache(tmp_path / "cache.json")
    monkeypatch.setattr(
        "guard_core.detection_engine.compiler._reach_probe_cost_verdict",
        lambda *a, **k: (False, TransientReason("deadline")),
    )
    compiler = PatternCompiler(validation_cache=cache)
    assert compiler.validate_pattern_safety("abc", max_content_length=CAP) == (
        False,
        "deadline",
    )
    assert len(cache) == 0


def test_an_old_format_file_is_read_without_error_and_serves_nothing(
    tmp_path: Path,
) -> None:
    path = tmp_path / "cache.json"
    old_key = hashlib.sha256(b"abc\x000").hexdigest()
    old = {
        old_key: {
            "safe": True,
            "reason": "old accept",
            "version": _validation_cache.ENGINE_VERSION,
        }
    }
    path.write_text(json.dumps(old), encoding="utf-8")
    cache = PatternValidationCache(path)
    assert len(cache) == 0
    assert cache.get("abc", 0, CAP) is None
    assert cache.get("abc", 0, DEFAULT_CAP) is None


def test_a_group_writable_file_is_not_trusted_and_never_rewritten(
    tmp_path: Path,
) -> None:
    path = tmp_path / "cache.json"
    PatternValidationCache(path).put("abc", 0, CAP, True, "ok")
    path.chmod(0o660)
    before = path.read_text(encoding="utf-8")
    cache = PatternValidationCache(path)
    assert cache.get("abc", 0, CAP) is None
    cache.put("zzz", 0, CAP, True, "ok")
    assert path.read_text(encoding="utf-8") == before


def test_a_world_writable_parent_directory_is_not_trusted(tmp_path: Path) -> None:
    directory = tmp_path / "shared"
    directory.mkdir()
    directory.chmod(0o777)
    cache = PatternValidationCache(directory / "cache.json")
    cache.put("abc", 0, CAP, True, "ok")
    assert cache.get("abc", 0, CAP) is None
    assert not (directory / "cache.json").exists()


def test_a_file_owned_by_another_user_is_not_trusted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "cache.json"
    PatternValidationCache(path).put("abc", 0, CAP, True, "ok")
    other_uid = os.getuid() + 1
    monkeypatch.setattr(_validation_cache.os, "getuid", lambda: other_uid)
    assert PatternValidationCache(path).get("abc", 0, CAP) is None


def test_an_unstatable_location_is_not_trusted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(self: Path, **kwargs: object) -> os.stat_result:
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "stat", broken)
    assert _validation_cache._is_trusted_location(tmp_path / "cache.json") is False


def test_trust_is_assumed_where_the_platform_has_no_uid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delattr(_validation_cache.os, "getuid")
    assert _validation_cache._is_trusted_location(tmp_path / "cache.json") is True


def test_the_cache_file_is_written_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "cache.json"
    PatternValidationCache(path).put("abc", 0, CAP, True, "ok")
    assert path.stat().st_mode & 0o777 == 0o600
