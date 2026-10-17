import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_CODE = (
    "import os, tests.conftest as a, tests.test_sync.conftest as b; "
    "print(a.REDIS_PREFIX, b.REDIS_PREFIX, os.getpid())"
)


def _prefixes(env_prefix: str | None) -> tuple[str, str]:
    env = {key: value for key, value in os.environ.items() if key != "REDIS_PREFIX"}
    if env_prefix is not None:
        env["REDIS_PREFIX"] = env_prefix
    result = subprocess.run(
        [sys.executable, "-c", _CODE],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    asynchronous, synchronous, _pid = result.stdout.split()[-3:]
    return asynchronous, synchronous


@pytest.mark.parametrize("env_prefix", [None, "test:guard_core:", "shared:"])
def test_no_suite_prefix_covers_another_suites_or_its_own_other_tree(
    env_prefix: str | None,
) -> None:
    first = _prefixes(env_prefix)
    second = _prefixes(env_prefix)
    every = [*first, *second]

    for index, prefix in enumerate(every):
        for other_index, other in enumerate(every):
            if index != other_index:
                assert not other.startswith(prefix), (prefix, other)
