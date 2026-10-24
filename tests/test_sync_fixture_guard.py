import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
VICTIM = "test_pattern_timeout_preserves_existing_regex_threat"
ASYNC_FILE = "tests/test_access_edges.py"
OTHER_ASYNC_FILE = "tests/test_scan_event_loop_yield.py"
SYNC_FILE = "tests/test_sync/test_access_edges.py"
SYNC_VICTIM_FILE = "tests/test_sync/test_sus_patterns/test_sus_patterns.py"


def _run(order: list[str]) -> subprocess.CompletedProcess[str]:
    return _run_all(order, "-k", VICTIM)


def _run_all(order: list[str], *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            *order,
            *extra,
            "--no-cov",
            "-p",
            "no:cacheprovider",
            "-q",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


def _async_conftest_plugin(config: pytest.Config) -> Any:
    return next(
        plugin
        for plugin in config.pluginmanager.get_plugins()
        if Path(getattr(plugin, "__file__", "") or "").resolve()
        == ROOT / "tests" / "conftest.py"
    )


def test_a_sync_test_that_resolves_an_async_fixture_fails_at_setup_with_the_rule(
    request: pytest.FixtureRequest,
) -> None:
    async_conftest = _async_conftest_plugin(request.config)
    sync_plugin = SimpleNamespace(
        __file__=str(ROOT / "tests" / "test_sync" / "conftest.py"),
        _isolate_event_handler_modules=lambda: None,
    )
    fake_request = SimpleNamespace(
        node=SimpleNamespace(
            path=ROOT / "tests" / "test_sync" / "test_x.py",
            nodeid="tests/test_sync/test_x.py::test_y",
        ),
        config=SimpleNamespace(
            pluginmanager=SimpleNamespace(get_plugins=lambda: [sync_plugin])
        ),
    )
    fixturedef = SimpleNamespace(
        func=async_conftest._isolate_event_handler_modules,
        argname="_isolate_event_handler_modules",
    )

    with pytest.raises(pytest.fail.Exception) as failure:
        async_conftest.pytest_fixture_setup(fixturedef, fake_request)

    message = str(failure.value)
    assert "is a sync test but fixture '" in message
    assert "resolved to the async one at" in message
    assert "tests/conftest.py" in message
    assert "contiguously" in message


def test_the_interleaved_order_passes() -> None:
    run = _run([OTHER_ASYNC_FILE, SYNC_FILE, ASYNC_FILE, SYNC_VICTIM_FILE])

    assert run.returncode == 0, run.stdout + run.stderr
    assert "TypeError" not in run.stdout + run.stderr


def test_async_and_sync_twins_interleaved_run_without_errors() -> None:
    run = _run_all(
        [
            "tests/test_compiler_cache.py",
            "tests/test_sync/test_compiler_cache.py",
            "tests/test_pattern_validation_cache.py",
            "tests/test_sync/test_pattern_validation_cache.py",
        ]
    )

    assert run.returncode == 0, run.stdout + run.stderr
    assert " error" not in run.stdout.splitlines()[-1]


def test_node_ids_that_mix_the_trees_pass() -> None:
    run = _run_all(
        [
            f"{SYNC_VICTIM_FILE}::test_pattern_timeout_preserves_existing_regex_threat",
            f"{ASYNC_FILE}",
            f"{SYNC_FILE}",
            f"{OTHER_ASYNC_FILE}",
        ]
    )

    assert run.returncode == 0, run.stdout + run.stderr
    assert "TypeError" not in run.stdout + run.stderr


def test_the_same_files_in_the_documented_order_pass() -> None:
    run = _run([OTHER_ASYNC_FILE, ASYNC_FILE, SYNC_FILE, SYNC_VICTIM_FILE])

    assert run.returncode == 0, run.stdout + run.stderr
