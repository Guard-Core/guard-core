from pathlib import Path

import pytest
from mypy import api as mypy_api

from guard_core.decorators import SecurityDecorator, get_route_id
from guard_core.models import SecurityConfig

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


def test_route_id_is_still_set_at_runtime_and_readable_through_the_helper() -> None:
    guard = SecurityDecorator(SecurityConfig())

    @guard.rate_limit(5, 60)
    def route() -> None:
        return None

    assert get_route_id(route) == route.__dict__["_guard_route_id"]


def test_route_id_of_an_undecorated_function_raises_attribute_error() -> None:
    def route() -> None:
        return None

    with pytest.raises(AttributeError, match="not decorated"):
        get_route_id(route)
