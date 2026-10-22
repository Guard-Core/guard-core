import importlib.metadata
import importlib.util
import re
from pathlib import Path
from types import ModuleType

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_PIN = re.compile(r'"ruff==([0-9][^"]*)"')
_OTHER_RUFF_VERSION_SOURCES = re.compile(
    r"ruff(==|>=|~=|<=|@)[0-9]|astral-sh/ruff-pre-commit|pip\s+install[^\n]*\bruff\b"
)


def _load_unasync() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "unasync_under_test", _ROOT / "scripts" / "unasync.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _entry_point_files() -> list[Path]:
    return [
        _ROOT / "Makefile",
        _ROOT / ".pre-commit-config.yaml",
        _ROOT / "Dockerfile",
        _ROOT / "compose.yml",
        *sorted((_ROOT / ".github" / "workflows").glob("*.yml")),
    ]


def test_pyproject_pins_exactly_one_ruff_version() -> None:
    pins = _PIN.findall((_ROOT / "pyproject.toml").read_text())
    assert len(set(pins)) == 1


def test_no_other_entry_point_names_a_ruff_version() -> None:
    offenders = [
        path.name
        for path in _entry_point_files()
        if path.is_file() and _OTHER_RUFF_VERSION_SOURCES.search(path.read_text())
    ]
    assert offenders == []


def test_installed_ruff_is_the_pinned_ruff() -> None:
    unasync = _load_unasync()
    assert importlib.metadata.version("ruff") == unasync.pinned_ruff_version()


def test_unasync_reads_the_pyproject_pin() -> None:
    unasync = _load_unasync()
    pins = _PIN.findall((_ROOT / "pyproject.toml").read_text())
    assert unasync.pinned_ruff_version() == pins[0]


def test_ruff_failure_prints_the_subprocess_stderr() -> None:
    unasync = _load_unasync()
    with pytest.raises(SystemExit) as raised:
        unasync.run_ruff("--no-such-ruff-flag")
    message = str(raised.value)
    assert "--no-such-ruff-flag" in message
    assert "exit code 2" in message
    assert "unexpected argument" in message


def test_missing_ruff_prints_the_interpreter_stderr(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    unasync = _load_unasync()
    bare_python = tmp_path / "bare_python"
    bare_python.write_text("#!/bin/sh\necho 'No module named ruff' >&2\nexit 1\n")
    bare_python.chmod(0o755)
    monkeypatch.setattr(unasync.sys, "executable", str(bare_python))
    with pytest.raises(SystemExit) as raised:
        unasync.run_ruff("--version")
    assert "No module named ruff" in str(raised.value)
