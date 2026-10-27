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


def test_a_non_callable_passed_to_a_route_decorator_is_a_type_error() -> None:
    stdout, stderr, status = mypy_api.run(
        [
            "--no-incremental",
            "--config-file",
            str(ROOT / "pyproject.toml"),
            str(FIXTURES / "expect_error" / "decorator_non_callable.py"),
        ]
    )
    assert status == 1, stdout + stderr
    assert "decorator_non_callable.py:6" in stdout
    assert 'Argument 1 has incompatible type "int"' in stdout
