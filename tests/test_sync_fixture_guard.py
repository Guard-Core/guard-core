import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VICTIM = "test_pattern_timeout_preserves_existing_regex_threat"
ASYNC_FILE = "tests/test_access_edges.py"
OTHER_ASYNC_FILE = "tests/test_scan_event_loop_yield.py"
SYNC_FILE = "tests/test_sync/test_access_edges.py"
SYNC_VICTIM_FILE = "tests/test_sync/test_sus_patterns/test_sus_patterns.py"


def _run(order: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            *order,
            "-k",
            VICTIM,
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


def test_a_sync_test_that_resolves_an_async_fixture_fails_at_setup_with_the_rule() -> (
    None
):
    run = _run([OTHER_ASYNC_FILE, SYNC_FILE, ASYNC_FILE, SYNC_VICTIM_FILE])

    output = run.stdout + run.stderr
    assert run.returncode != 0
    assert "is a sync test but fixture '" in output
    assert "resolved to the async one at" in output
    assert "tests/conftest.py" in output
    assert "tests/test_sync/conftest.py" in output
    assert "contiguously" in output
    assert "TypeError" not in output


def test_the_same_files_in_the_documented_order_pass() -> None:
    run = _run([OTHER_ASYNC_FILE, ASYNC_FILE, SYNC_FILE, SYNC_VICTIM_FILE])

    assert run.returncode == 0, run.stdout + run.stderr
