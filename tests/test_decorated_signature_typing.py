from pathlib import Path

import pytest
from mypy import api as mypy_api

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "typing_fixtures"


@pytest.mark.parametrize(
    "fixture", ["decorated_signature.py", "decorated_signature_sync.py"]
)
def test_decorated_function_keeps_its_signature_for_type_checkers(
    fixture: str,
) -> None:
    stdout, stderr, status = mypy_api.run(
        [
            "--no-incremental",
            "--config-file",
            str(ROOT / "pyproject.toml"),
            str(FIXTURES / fixture),
        ]
    )
    assert status == 0, stdout + stderr
