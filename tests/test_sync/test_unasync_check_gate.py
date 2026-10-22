import importlib.util
import re
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

import pytest


def _repo_root() -> Path:
    for candidate in Path(__file__).resolve().parents:
        if (candidate / "scripts" / "unasync.py").is_file():
            return candidate
    raise FileNotFoundError("scripts/unasync.py not found above this test file")


def _load_unasync_module() -> ModuleType:
    root = _repo_root()
    spec = importlib.util.spec_from_file_location(
        "unasync_check_gate_probe", root / "scripts" / "unasync.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git_status_short(root: Path) -> str:
    result = subprocess.run(
        ["git", "status", "--short"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


@pytest.mark.parametrize("failure_at", [1, 2, 3])
def test_generation_fails_when_a_formatter_fails(failure_at: int) -> None:
    module = _load_unasync_module()
    version = subprocess.CompletedProcess(
        [], 0, stdout=f"ruff {module.pinned_ruff_version()}\n", stderr=""
    )
    passed = subprocess.CompletedProcess([], 0, stdout="", stderr="")
    failed = subprocess.CompletedProcess([], 1, stdout="", stderr="ruff exploded")
    results = [version, *[passed] * (failure_at - 1), failed]
    with patch("subprocess.run", side_effect=results) as run:
        with pytest.raises(SystemExit, match="ruff exploded"):
            module.format_generated()
    assert run.call_count == failure_at + 1


def test_check_flags_a_missing_sync_mirror_instead_of_hiding_it() -> None:
    root = _repo_root()
    probe = root / "tests" / "test_unasync_check_gate_probe.py"
    probe_mirror = root / "tests" / "test_sync" / "test_unasync_check_gate_probe.py"
    assert not probe.exists()
    assert not probe_mirror.exists()
    probe.write_text("def test_probe() -> None:\n    assert True\n")
    try:
        result = subprocess.run(
            [sys.executable, str(root / "scripts" / "unasync.py"), "--check"],
            cwd=root,
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0
        assert f"MISSING: {probe_mirror}" in result.stdout
        assert not probe_mirror.exists()
    finally:
        probe.unlink(missing_ok=True)
        probe_mirror.unlink(missing_ok=True)


def test_check_flags_an_orphaned_sync_mirror_instead_of_hiding_it() -> None:
    root = _repo_root()
    orphan = root / "tests" / "test_sync" / "test_unasync_check_gate_orphan_probe.py"
    assert not orphan.exists()
    orphan.write_text("def test_probe() -> None:\n    assert True\n")
    try:
        result = subprocess.run(
            [sys.executable, str(root / "scripts" / "unasync.py"), "--check"],
            cwd=root,
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0
        assert f"ORPHAN: {orphan}" in result.stdout
    finally:
        orphan.unlink(missing_ok=True)


def test_check_sweeps_a_stale_tmp_dir_from_a_previous_crashed_run() -> None:
    root = _repo_root()
    stale = root / ".unasync_check_tmp_stale_probe"
    stale.mkdir()
    (stale / "leftover.txt").write_text("debris")
    try:
        subprocess.run(
            [sys.executable, str(root / "scripts" / "unasync.py"), "--check"],
            cwd=root,
            capture_output=True,
            text=True,
        )
        assert not stale.exists()
    finally:
        if stale.exists():
            shutil.rmtree(stale)


def test_permission_error_creating_tmp_dir_gives_a_clean_message(
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_unasync_module()

    def raising_mkdtemp(*args: object, **kwargs: object) -> str:
        raise PermissionError("Permission denied")

    with patch("tempfile.mkdtemp", raising_mkdtemp):
        with pytest.raises(SystemExit) as exc_info:
            module._make_check_tmp_dir()

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "cannot create a temporary directory" in captured.out
    assert "Permission denied" in captured.out


def _test_function_names(path: Path) -> set[str]:
    return set(re.findall(r"(?m)^(?:async )?def (test_\w+)\(", path.read_text()))


_HAND_MAINTAINED_PROVIDER_LIFECYCLE_FILES = (
    "test_otel_handler_provider_lifecycle.py",
    "test_logfire_handler_provider_lifecycle.py",
)


def test_hand_maintained_provider_lifecycle_pairs_test_names_match() -> None:
    root = _repo_root()
    for filename in _HAND_MAINTAINED_PROVIDER_LIFECYCLE_FILES:
        async_path = root / "tests" / filename
        sync_path = root / "tests" / "test_sync" / filename
        async_names = _test_function_names(async_path)
        sync_names = _test_function_names(sync_path)
        assert async_names, f"no test functions found in {async_path}"
        assert async_names == sync_names, (
            f"{filename}: only in async: {async_names - sync_names}; "
            f"only in sync: {sync_names - async_names}"
        )


def test_check_leaves_the_working_tree_byte_identical_on_a_dirty_repo() -> None:
    root = _repo_root()
    status_before = _git_status_short(root)

    result = subprocess.run(
        [sys.executable, str(root / "scripts" / "unasync.py"), "--check"],
        cwd=root,
        capture_output=True,
        text=True,
    )

    status_after = _git_status_short(root)
    assert status_before == status_after
    assert result.returncode == 0


def test_the_formatter_runs_the_interpreters_own_ruff_not_uv_run() -> None:
    unasync = _load_unasync_module()
    commands: list[list[str]] = []

    def record(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(
            command, 0, stdout=f"ruff {unasync.pinned_ruff_version()}\n", stderr=""
        )

    with patch.object(subprocess, "run", record):
        unasync.format_generated()

    assert len(commands) == 4
    assert all(command[:3] == [sys.executable, "-m", "ruff"] for command in commands)
