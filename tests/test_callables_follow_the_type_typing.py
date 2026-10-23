from pathlib import Path

from mypy import api as mypy_api

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "typing_fixtures"


def test_async_and_sync_callables_type_check_in_the_config_without_a_cast() -> None:
    stdout, stderr, status = mypy_api.run(
        [
            "--no-incremental",
            "--config-file",
            str(FIXTURES / "adapter_mypy.ini"),
            str(FIXTURES / "sync_callables_in_config.py"),
        ]
    )
    assert status == 0, stdout + stderr
