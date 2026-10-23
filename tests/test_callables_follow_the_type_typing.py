from pathlib import Path

import pytest
from mypy import api as mypy_api

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "typing_fixtures"


def _mypy(fixture: str) -> tuple[str, str, int]:
    return mypy_api.run(
        [
            "--no-incremental",
            "--config-file",
            str(FIXTURES / "adapter_mypy.ini"),
            str(FIXTURES / fixture),
        ]
    )


@pytest.mark.parametrize(
    "fixture", ["sync_callables_in_config.py", "generic_config_trees.py"]
)
def test_each_tree_type_checks_its_own_config_without_a_cast(fixture: str) -> None:
    stdout, stderr, status = _mypy(fixture)
    assert status == 0, stdout + stderr


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        (
            "expect_error/generic_config_wsgi_in_async_tree.py",
            'incompatible type "SecurityConfig[SyncGuardRequest]"; '
            'expected "SecurityConfig[GuardRequest]"',
        ),
        (
            "expect_error/generic_config_async_in_sync_tree.py",
            'incompatible type "SecurityConfig[GuardRequest]"; '
            'expected "SecurityConfig[SyncGuardRequest]"',
        ),
        (
            "expect_error/auth_verifier_wrong_signature.py",
            'Argument "auth_verifier" to "SecurityConfig" has incompatible type',
        ),
    ],
)
def test_a_config_of_the_other_tree_or_a_wrong_verifier_is_a_type_error(
    fixture: str, expected: str
) -> None:
    stdout, stderr, status = _mypy(fixture)
    assert status == 1, stdout + stderr
    assert expected in stdout


@pytest.mark.parametrize(
    ("config_file", "revealed"),
    [
        (
            "pyproject.toml",
            "guard_core.models.SecurityConfig"
            "[guard_core.protocols.request_protocol.GuardRequest]",
        ),
        (
            "tests/typing_fixtures/adapter_mypy.ini",
            "guard_core.models.SecurityConfig"
            "[guard_core.sync.protocols.request_protocol.SyncGuardRequest]",
        ),
    ],
    ids=["with-the-pydantic-mypy-plugin", "without-the-plugin"],
)
def test_a_sync_check_picks_the_wsgi_config_only_without_the_pydantic_plugin(
    config_file: str, revealed: str
) -> None:
    stdout, stderr, status = mypy_api.run(
        [
            "--no-incremental",
            "--config-file",
            str(ROOT / config_file),
            str(FIXTURES / "inferred_config_type.py"),
        ]
    )
    assert status == 0, stdout + stderr
    assert f'Revealed type is "{revealed}"' in stdout
