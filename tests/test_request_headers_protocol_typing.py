from pathlib import Path

from mypy import api as mypy_api

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "typing_fixtures" / "request_headers_protocol.py"


def test_a_dict_and_a_pair_iterating_container_are_request_headers() -> None:
    stdout, stderr, status = mypy_api.run(
        [
            "--no-incremental",
            "--config-file",
            str(ROOT / "pyproject.toml"),
            str(FIXTURE),
        ]
    )
    assert status == 0, stdout + stderr
